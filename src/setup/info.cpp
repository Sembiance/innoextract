/*
 * Copyright (C) 2011-2020 Daniel Scharrer
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the author(s) be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */

#include "setup/info.hpp"

#include <cassert>
#include <cstring>
#include <ctime>
#include <istream>
#include <sstream>

#include <boost/foreach.hpp>

#include "crypto/hasher.hpp"
#include "crypto/pbkdf2.hpp"
#include "crypto/sha256.hpp"
#include "crypto/xchacha20.hpp"
#include "setup/component.hpp"
#include "setup/data.hpp"
#include "setup/delete.hpp"
#include "setup/directory.hpp"
#include "setup/file.hpp"
#include "setup/icon.hpp"
#include "setup/ini.hpp"
#include "setup/item.hpp"
#include "setup/language.hpp"
#include "setup/message.hpp"
#include "setup/permission.hpp"
#include "setup/registry.hpp"
#include "setup/run.hpp"
#include "setup/task.hpp"
#include "setup/type.hpp"
#include "stream/block.hpp"
#include "util/endian.hpp"
#include "util/fstream.hpp"
#include "util/load.hpp"
#include "util/log.hpp"
#include "util/output.hpp"

namespace setup {

template <class Entry>
void info::load_entries(std::istream & is, entry_types entries, size_t count,
                        std::vector<Entry> & result, entry_types::enum_type entry_type) {

	// For version < 1.3.0, entries are serialized with a 4-byte TotalSize prefix
	// (SEDeflateBlockWrite format). We read TotalSize to compute the entry end position
	// and seek there after loading, handling format differences between sub-versions.
	// Only apply this to seekable streams (the data entry block uses zlib and isn't seekable).
	bool use_entry_size = false;
	if(version < INNO_VERSION(1, 3, 0)) {
		std::ios_base::iostate saved_exc = is.exceptions();
		is.exceptions(std::ios_base::goodbit);
		std::streampos test_pos = is.tellg();
		is.clear();
		is.exceptions(saved_exc);
		use_entry_size = (test_pos != std::streampos(-1));
	}

	result.clear();
	if(entries & entry_type) {
		result.resize(count);
		for(size_t i = 0; i < count; i++) {
			std::streampos entry_end;
			if(use_entry_size) {
				boost::uint32_t entry_size = util::load<boost::uint32_t>(is);
				entry_end = is.tellg() + std::streamoff(entry_size);
			}
			result[i].load(is, *this);
			if(use_entry_size) {
				std::ios_base::iostate old_exceptions = is.exceptions();
				is.exceptions(std::ios_base::goodbit);
				is.clear();
				is.seekg(entry_end);
				is.clear();
				is.exceptions(old_exceptions);
			}
		}
	} else {
		for(size_t i = 0; i < count; i++) {
			std::streampos entry_end;
			if(use_entry_size) {
				boost::uint32_t entry_size = util::load<boost::uint32_t>(is);
				entry_end = is.tellg() + std::streamoff(entry_size);
			}
			Entry entry;
			entry.load(is, *this);
			if(use_entry_size) {
				std::ios_base::iostate old_exceptions = is.exceptions();
				is.exceptions(std::ios_base::goodbit);
				is.clear();
				is.seekg(entry_end);
				is.clear();
				is.exceptions(old_exceptions);
			}
		}
	}
}

namespace {

void load_wizard_images(std::istream & is, const setup::version & version,
                        std::vector<std::string> & images, info::entry_types entries) {
	
	size_t count = 1;
	if(version >= INNO_VERSION(5, 6, 0)) {
		count = util::load<boost::uint32_t>(is);
	}
	
	if(entries & (info::WizardImages | info::NoSkip)) {
		images.resize(count);
		for(size_t i = 0; i < count; i++) {
			is >> util::binary_string(images[i]);
		}
		if(version < INNO_VERSION(5, 6, 0) && images[0].empty()) {
			images.clear();
		}
	} else {
		for(size_t i = 0; i < count; i++) {
			util::binary_string::skip(is);
		}
	}
	
}

void load_wizard_and_decompressor(std::istream & is, const setup::version & version,
                                  const setup::header & header,
                                  setup::info & info, info::entry_types entries) {
	
	info.wizard_images.clear();
	info.wizard_images_small.clear();
	
	load_wizard_images(is, version, info.wizard_images, entries);
	
	if(version >= INNO_VERSION(2, 0, 0) || version.is_isx()) {
		load_wizard_images(is, version, info.wizard_images_small, entries);
	}
	
	info.decompressor_dll.clear();
	if(header.compression == stream::BZip2
	   || (header.compression == stream::LZMA1 && version == INNO_VERSION(4, 1, 5))
	   || (header.compression == stream::Zlib && version >= INNO_VERSION(4, 2, 6))) {
		if(entries & (info::DecompressorDll | info::NoSkip)) {
			is >> util::binary_string(info.decompressor_dll);
		} else {
			// decompressor dll - we don't need this
			util::binary_string::skip(is);
		}
	}
	
	info.decrypt_dll.clear();
	if((header.options & header::EncryptionUsed) && version < INNO_VERSION(6, 4, 0)) {
		if(entries & (info::DecryptDll | info::NoSkip)) {
			is >> util::binary_string(info.decrypt_dll);
		} else {
			// decrypt dll - we don't need this
			util::binary_string::skip(is);
		}
	}
	
}

void check_is_end(stream::block_reader::pointer & is, const char * what) {
	is->exceptions(std::ios_base::goodbit);
	char dummy;
	if(!is->get(dummy).eof()) {
		throw std::ios_base::failure(what);
	}
}

} // anonymous namespace

void info::load_v109(std::istream & is, entry_types entries) {

	debug("loading setup headers for version " << version << " (pre-1.2.10 path)");

	codepage = util::cp_windows1252;

	// Pre-1.2.10 block format: checksum1(4) + compressed_size(4) + uncompressed_size(4)
	//   + checksum2(4) + data. compressed_size=0xFFFFFFFF means stored (uncompressed).
	// Track stream positions manually because boost::iostreams chains
	// don't reliably leave the base stream at the right position after destruction.

	std::streampos block_start = is.tellg();

	// Helper lambda to get block compressed size and advance block_start
	auto advance_block = [&]() {
		is.seekg(block_start);
		(void)util::load<boost::uint32_t>(is); // checksum1
		boost::uint32_t comp = util::load<boost::uint32_t>(is);
		boost::uint32_t uncomp = util::load<boost::uint32_t>(is);
		(void)util::load<boost::uint32_t>(is); // checksum2
		if(comp == boost::uint32_t(-1)) {
			block_start += std::streamoff(16 + uncomp);
		} else {
			block_start += std::streamoff(16 + comp);
		}
	};

	// Block 0: Header
	{
		is.seekg(block_start);
		std::streampos saved = block_start;
		advance_block();
		is.seekg(saved);
		stream::block_reader::pointer reader = stream::block_reader::get(is, version);
		header.load(*reader, version);
		header.decode(codepage);
	}

	// Block 1: Messages/license text (skip)
	advance_block();

	if(version <= INNO_VERSION(1, 0, 9)) {
		// 1.0.9/1.0.8 format: file entries follow directly, each in own block
		// 32-bit: 95-byte entries (Pascal[63] + fixed data)
		// 16-bit: 94-byte entries (4-byte prefix + Pascal[63] + fixed data)
		size_t file_count = header.file_count;
		bool is_16bit = (version.bits() == 16);

		files.clear();
		data_entries.clear();
		if(entries & (Files | DataEntries)) {
			files.resize(file_count);
			data_entries.resize(file_count);
		}

		// 16-bit data files have no disk header; 32-bit have 12-byte idska32 header
		boost::uint32_t current_offset = is_16bit ? 0 : 12;
		size_t entry_size = is_16bit ? 94 : 95;
		for(size_t i = 0; i < file_count; i++) {
			is.seekg(block_start);
			std::streampos saved = block_start;
			advance_block();
			is.seekg(saved);
			stream::block_reader::pointer reader = stream::block_reader::get(is, version);

			char entry_buf[95];
			reader->read(entry_buf, std::streamsize(entry_size));
			if(reader->fail()) {
				std::ostringstream oss;
				oss << "could not read file entry " << i;
				throw std::runtime_error(oss.str());
			}

			std::string dest_path;
			size_t filetime_offset;
			if(is_16bit) {
				// 16-bit: 4-byte prefix + Pascal[63] path
				boost::uint8_t path_len = static_cast<boost::uint8_t>(entry_buf[4]);
				if(path_len > 63) { path_len = 63; }
				dest_path.assign(entry_buf + 5, path_len);
				filetime_offset = 68;
			} else {
				// 32-bit: Pascal[63] path at offset 0
				boost::uint8_t path_len = static_cast<boost::uint8_t>(entry_buf[0]);
				if(path_len > 63) { path_len = 63; }
				dest_path.assign(entry_buf + 1, path_len);
				filetime_offset = 64;
			}

			// Sizes are at the same offsets for both formats
			boost::uint32_t uncompressed_size = util::little_endian::load<boost::uint32_t>(entry_buf + 80);
			boost::uint32_t compressed_size = util::little_endian::load<boost::uint32_t>(entry_buf + 84);
			boost::uint32_t checksum_val = util::little_endian::load<boost::uint32_t>(entry_buf + 88);

			debug("[file " << i << "] \"" << dest_path << "\" compressed=" << compressed_size
			      << " uncompressed=" << uncompressed_size);

			if(entries & (Files | DataEntries)) {
				file_entry & fe = files[i];
				fe.destination = dest_path;
				fe.location = static_cast<boost::uint32_t>(i);
				fe.options = 0;
				fe.type = file_entry::UserFile;
				fe.attributes = boost::uint32_t(-1);
				fe.external_size = 0;
				fe.permission = -1;
				fe.size = uncompressed_size;
				fe.checksum.type = crypto::Adler32;
				fe.checksum.adler32 = checksum_val;

				data_entry & de = data_entries[i];
				de.chunk.first_slice = 0;
				de.chunk.last_slice = 0;
				de.chunk.sort_offset = current_offset;
				de.chunk.offset = current_offset;
				de.chunk.size = compressed_size;
				de.chunk.compression = stream::Zlib;
				de.chunk.encryption = stream::Plaintext;
				de.file.offset = 0;
				de.file.size = uncompressed_size;
				de.file.checksum.type = crypto::Adler32;
				de.file.checksum.adler32 = checksum_val;
				de.file.filter = stream::NoFilter;
				de.uncompressed_size = uncompressed_size;
				de.timestamp = 0;
				de.timestamp_nsec = 0;
				de.file_version = 0;
				de.options = 0;
				de.sign = data_entry::NoSetting;

				if(is_16bit) {
					// 16-bit: DOS date+time packed in uint32 (low=time, high=date)
					boost::uint16_t dos_time = util::little_endian::load<boost::uint16_t>(entry_buf + filetime_offset);
					boost::uint16_t dos_date = util::little_endian::load<boost::uint16_t>(entry_buf + filetime_offset + 2);
					if(dos_date != 0) {
						int day   = dos_date & 0x1f;
						int month = (dos_date >> 5) & 0xf;
						int year  = ((dos_date >> 9) & 0x7f) + 1980;
						int sec   = (dos_time & 0x1f) * 2;
						int min   = (dos_time >> 5) & 0x3f;
						int hour  = (dos_time >> 11) & 0x1f;
						// Convert to Unix timestamp (approximate, ignoring leap seconds)
						struct std::tm tm_val;
						std::memset(&tm_val, 0, sizeof(tm_val));
						tm_val.tm_year = year - 1900;
						tm_val.tm_mon  = month - 1;
						tm_val.tm_mday = day;
						tm_val.tm_hour = hour;
						tm_val.tm_min  = min;
						tm_val.tm_sec  = sec;
						tm_val.tm_isdst = -1;
						std::time_t t = std::mktime(&tm_val);
						if(t != std::time_t(-1)) {
							de.timestamp = boost::int64_t(t);
						}
					}
				} else {
					// 32-bit: Windows FILETIME (100ns intervals since 1601-01-01)
					boost::int64_t filetime;
					std::memcpy(&filetime, entry_buf + filetime_offset, sizeof(filetime));
					static const boost::int64_t FiletimeOffset = 0x19DB1DED53E8000ll;
					if(filetime >= FiletimeOffset) {
						filetime -= FiletimeOffset;
						de.timestamp = filetime / 10000000;
						de.timestamp_nsec = boost::uint32_t(filetime % 10000000) * 100;
					}
				}

				current_offset += 4 + compressed_size;
			}
		}

		header.data_entry_count = file_count;
	} else {
		// 1.1.x format: directory entries + file entries + data entries + icons + registry + ...
		size_t dir_count = header.directory_count;
		size_t file_count = header.file_count;

		debug("loading " << dir_count << " directories, " << file_count << " files");

		// Skip directory entry blocks
		for(size_t i = 0; i < dir_count; i++) {
			advance_block();
		}

		// File entry blocks: 2 binary strings + winver(8) + fixed data(35 bytes)
		files.clear();
		data_entries.clear();
		if(entries & (Files | DataEntries)) {
			files.resize(file_count);
			data_entries.resize(file_count);
		}

		for(size_t i = 0; i < file_count; i++) {
			is.seekg(block_start);
			std::streampos saved = block_start;
			advance_block();
			is.seekg(saved);
			stream::block_reader::pointer reader = stream::block_reader::get(is, version);

			// Read destination path (binary string)
			std::string dest_path;
			*reader >> util::binary_string(dest_path);

			// Read source path (binary string, usually empty)
			std::string source_path;
			*reader >> util::binary_string(source_path);

			// Read winver (8 bytes) - skip
			char winver_buf[8];
			reader->read(winver_buf, 8);

			// Fixed data: 8 FILETIME + 8 file_version + 4 uncomp + 4 comp + 4 checksum + 4 unknown + 3 flags
			char fixed[35];
			reader->read(fixed, 35);
			if(reader->fail()) {
				std::ostringstream oss;
				oss << "could not read file entry " << i;
				throw std::runtime_error(oss.str());
			}

			boost::int64_t filetime;
			std::memcpy(&filetime, fixed + 0, sizeof(filetime));

			boost::uint32_t file_version_ms = util::little_endian::load<boost::uint32_t>(fixed + 8);
			boost::uint32_t file_version_ls = util::little_endian::load<boost::uint32_t>(fixed + 12);
			boost::uint32_t uncompressed_size = util::little_endian::load<boost::uint32_t>(fixed + 16);
			boost::uint32_t compressed_size = util::little_endian::load<boost::uint32_t>(fixed + 20);
			boost::uint32_t checksum_val = util::little_endian::load<boost::uint32_t>(fixed + 24);

			debug("[file " << i << "] \"" << dest_path << "\" compressed=" << compressed_size
			      << " uncompressed=" << uncompressed_size);

			if(entries & (Files | DataEntries)) {
				file_entry & fe = files[i];
				fe.destination = dest_path;
				fe.source = source_path;
				fe.location = static_cast<boost::uint32_t>(i);
				fe.options = 0;
				fe.type = file_entry::UserFile;
				fe.attributes = boost::uint32_t(-1);
				fe.external_size = 0;
				fe.permission = -1;
				fe.size = uncompressed_size;
				fe.checksum.type = crypto::Adler32;
				fe.checksum.adler32 = checksum_val;

				data_entry & de = data_entries[i];
				de.chunk.compression = stream::Zlib;
				de.chunk.encryption = stream::Plaintext;
				de.file.offset = 0;
				de.file.size = uncompressed_size;
				de.file.checksum.type = crypto::Adler32;
				de.file.checksum.adler32 = checksum_val;
				de.file.filter = stream::NoFilter;
				de.uncompressed_size = uncompressed_size;
				de.chunk.size = compressed_size;
				de.file_version = (boost::uint64_t(file_version_ms) << 32) | file_version_ls;
				de.options = 0;
				de.sign = data_entry::NoSetting;

				static const boost::int64_t FiletimeOffset = 0x19DB1DED53E8000ll;
				if(filetime >= FiletimeOffset) {
					filetime -= FiletimeOffset;
					de.timestamp = filetime / 10000000;
					de.timestamp_nsec = boost::uint32_t(filetime % 10000000) * 100;
				} else {
					de.timestamp = 0;
					de.timestamp_nsec = 0;
				}

				// Placeholder offsets - will be filled from data entry blocks
				de.chunk.first_slice = 0;
				de.chunk.last_slice = 0;
				de.chunk.sort_offset = 0;
				de.chunk.offset = 0;
			}
		}

		// Data entry blocks: 12 bytes each (first_slice + last_slice + offset)
		for(size_t i = 0; i < file_count; i++) {
			is.seekg(block_start);
			std::streampos saved = block_start;
			advance_block();
			is.seekg(saved);
			stream::block_reader::pointer reader = stream::block_reader::get(is, version);

			boost::uint32_t first_slice = util::load<boost::uint32_t>(*reader);
			boost::uint32_t last_slice = util::load<boost::uint32_t>(*reader);
			boost::uint32_t offset = util::load<boost::uint32_t>(*reader);

			// Slice numbers are 1-based in pre-4.0.0
			if(first_slice >= 1) { first_slice--; }
			if(last_slice >= 1) { last_slice--; }

			if((entries & (Files | DataEntries)) && i < data_entries.size()) {
				data_entry & de = data_entries[i];
				de.chunk.first_slice = first_slice;
				de.chunk.last_slice = last_slice;
				de.chunk.sort_offset = offset;
				de.chunk.offset = offset;
			}
		}

		// Skip remaining entry blocks (icons, ini, registry, delete, run, etc.)
		size_t remaining = header.icon_count + header.ini_entry_count
		                 + header.registry_entry_count + header.delete_entry_count
		                 + header.uninstall_delete_entry_count + header.run_entry_count
		                 + header.uninstall_run_entry_count;
		for(size_t i = 0; i < remaining; i++) {
			advance_block();
		}

		header.data_entry_count = file_count;
	}

	// Clear unused entry vectors
	languages.clear();
	messages.clear();
	permissions.clear();
	types.clear();
	components.clear();
	tasks.clear();
	directories.clear();
	icons.clear();
	ini_entries.clear();
	registry_entries.clear();
	delete_entries.clear();
	uninstall_delete_entries.clear();
	run_entries.clear();
	uninstall_run_entries.clear();
	wizard_images.clear();
	wizard_images_small.clear();
	decompressor_dll.clear();
	decrypt_dll.clear();
}

void info::try_load(std::istream & is, entry_types entries, util::codepage_id force_codepage) {
	
	debug("trying to load setup headers for version " << version);
	
	if((entries & (Messages | NoSkip)) || (!version.is_unicode() && !force_codepage)) {
		entries |= Languages;
	}
	
	std::streampos block1_start = is.tellg();
	stream::block_reader::pointer reader = stream::block_reader::get(is, version);

	if(version >= INNO_VERSION(1, 2, 0) && version < INNO_VERSION(1, 3, 0)) {
		// 1.2.x blocks use CRC-per-4K chunks (non-seekable), but TotalSize-based
		// entry loading needs seeking. Buffer the decompressed block into a seekable stream.
		std::ostringstream oss;
		oss << reader->rdbuf();
		reader.reset(new std::istringstream(oss.str()));
		reader->exceptions(std::ios_base::badbit | std::ios_base::failbit);
	}

	header.load(*reader, version);

	load_entries(*reader, entries, header.language_count, languages, Languages);


	if(version.is_unicode()) {
		// Unicode installers are always UTF16-LE, do not allow users to override that.
		codepage = util::cp_utf16le;
	} else if(force_codepage) {
		codepage = force_codepage;
	} else if(languages.empty()) {
		codepage = util::cp_windows1252;
	} else {
		// Non-Unicode installers do not have a defined codepage but instead just assume the
		// codepage of the system the installer is run on.
		// Look at the list of available languages to guess a suitable codepage.
		codepage = languages[0].codepage;
		BOOST_FOREACH(const language_entry & language, languages) {
			if(language.codepage == util::cp_windows1252) {
				codepage = util::cp_windows1252;
				break;
			}
		}
	}
	
	header.decode(codepage);
	BOOST_FOREACH(language_entry & language, languages) {
		language.decode(codepage);
	}
	
	if(version < INNO_VERSION(4, 0, 0)) {
		load_wizard_and_decompressor(*reader, version, header, *this, entries);
	}

	load_entries(*reader, entries, header.message_count, messages, Messages);
	load_entries(*reader, entries, header.permission_count, permissions, Permissions);
	load_entries(*reader, entries, header.type_count, types, Types);
	load_entries(*reader, entries, header.component_count, components, Components);
	load_entries(*reader, entries, header.task_count, tasks, Tasks);
	load_entries(*reader, entries, header.directory_count, directories, Directories);
	load_entries(*reader, entries, header.file_count, files, Files);
	load_entries(*reader, entries, header.icon_count, icons, Icons);
	load_entries(*reader, entries, header.ini_entry_count, ini_entries, IniEntries);
	load_entries(*reader, entries, header.registry_entry_count, registry_entries, RegistryEntries);
	load_entries(*reader, entries, header.delete_entry_count, delete_entries, DeleteEntries);
	load_entries(*reader, entries, header.uninstall_delete_entry_count, uninstall_delete_entries,
	             UninstallDeleteEntries);
	load_entries(*reader, entries, header.run_entry_count, run_entries, RunEntries);
	load_entries(*reader, entries, header.uninstall_run_entry_count, uninstall_run_entries,
	             UninstallRunEntries);

	if(version >= INNO_VERSION(4, 0, 0)) {
		load_wizard_and_decompressor(*reader, version, header, *this, entries);
	}

	// restart the compression stream
	check_is_end(reader, "unknown data at end of primary header stream");

	if(version < INNO_VERSION(1, 2, 0)) {
		// For pre-1.2.0, restrict(base, 0, stored_size) leaves the base stream at
		// position stored_size instead of data_start + stored_size. Re-parse the
		// block 1 header to compute the correct position for block 2.
		is.seekg(block1_start);
		(void)util::load<boost::uint32_t>(is); // checksum1
		boost::uint32_t comp = util::load<boost::uint32_t>(is);
		boost::uint32_t uncomp = util::load<boost::uint32_t>(is);
		(void)util::load<boost::uint32_t>(is); // checksum2
		boost::uint32_t data_size = (comp == boost::uint32_t(-1)) ? uncomp : comp;
		is.seekg(block1_start + std::streamoff(16 + data_size));
	}

	reader = stream::block_reader::get(is, version);

	load_entries(*reader, entries, header.data_entry_count, data_entries, DataEntries);

	check_is_end(reader, "unknown data at end of secondary header stream");
}

void info::load(std::istream & is, entry_types entries, util::codepage_id force_codepage) {
	
	version.load(is);
	
	if(!version.known) {
		if(entries & NoUnknownVersion) {
			std::ostringstream oss;
			oss << "Unexpected setup data version: " << version;
			throw std::runtime_error(oss.str());
		}
		log_warning << "Unexpected setup data version: "
		            << color::white << version << color::reset;
	}
	
	if(version < INNO_VERSION(1, 2, 0)) {
		load_v109(is, entries);
		return;
	}

	version_constant listed_version = version.value;

	// Some setup versions didn't increment the data version number when they should have.
	// To work around this, we try to parse the headers for all data versions and use the first
	// version that parses without warnings or errors.
	bool ambiguous = !version.known || version.is_ambiguous();
	if(version.is_ambiguous()) {
		// Force parsing all headers so that we don't miss any errors.
		entries |= NoSkip;
	}
	
	bool parsed_without_errors = false;
	std::streampos start = is.tellg();
	for(;;) {
		
		warning_suppressor warnings;
		
		try {

			// Try to parse headers for this version
			try_load(is, entries, force_codepage);

			if(warnings) {
				// Parsed without errors but with warnings - try other versions first
				if(!parsed_without_errors) {
					listed_version = version.value;
					parsed_without_errors = true;
				}
				throw std::exception();
			}

			warnings.flush();
			return;

		} catch(...) {
			
			is.clear();
			is.seekg(start);
			
			version_constant next_version = version.next();
			
			if(!ambiguous || !next_version) {
				if(version.value != listed_version) {
					// Rewind to a previous version that had better results and report those
					version.value = listed_version;
					warnings.restore();
					try_load(is, entries, force_codepage);
				} else {
					// Otherwise. report results for the current version
					warnings.flush();
					if(!parsed_without_errors) {
						throw;
					}
				}
				return;
			}
			
			// Retry with the next version
			version.value = next_version;
			ambiguous = version.is_ambiguous();
			
		}
		
	}
	
}

std::string info::get_key(const std::string & password) {
	
	std::string encoded_password;
	util::from_utf8(password, encoded_password, codepage);
	
	if(header.password.type == crypto::PBKDF2_SHA256_XChaCha20) {
		
		#if INNOEXTRACT_HAVE_DECRYPTION
		
		// 16 bytes PBKDF2 salt + 4 bytes PBKDF2 iterations + 24 bytes ChaCha20 base nonce
		if(header.password_salt.length() != 20 + crypto::xchacha20::nonce_size) {
			throw std::runtime_error("unexpected password salt size");
		}
		
		std::string result;
		result.resize(crypto::xchacha20::key_size + crypto::xchacha20::nonce_size);
		typedef crypto::pbkdf2<crypto::sha256> pbkdf2;
		pbkdf2::derive(encoded_password.c_str(), encoded_password.length(), &header.password_salt[0], 16,
		               util::little_endian::load<boost::uint32_t>(&header.password_salt[16]), &result[0],
		               crypto::xchacha20::key_size);
		
		std::memcpy(&result[crypto::xchacha20::key_size], &header.password_salt[20],
		            crypto::xchacha20::nonce_size);
		
		return result;
		
		#endif
		
	}
	
	return encoded_password;
}

bool info::check_key(const std::string & key) {
	
	if(header.password.type == crypto::PBKDF2_SHA256_XChaCha20) {
		
		#if INNOEXTRACT_HAVE_DECRYPTION
		
		if(key.length() != crypto::xchacha20::key_size + crypto::xchacha20::nonce_size) {
			throw std::runtime_error("unexpected key size");
		}
		
		crypto::xchacha20 cipher;
		
		char nonce[crypto::xchacha20::nonce_size];
		std::memcpy(nonce, key.c_str() + crypto::xchacha20::key_size, crypto::xchacha20::nonce_size);
		*reinterpret_cast<boost::uint32_t *>(nonce + 8) = ~*reinterpret_cast<boost::uint32_t *>(nonce + 8);
		cipher.init(key.c_str(), nonce);
		
		char buffer[] = { 0, 0, 0, 0 };
		cipher.crypt(buffer, buffer, sizeof(buffer));
		
		return (std::memcmp(buffer, header.password.check, sizeof(buffer)) == 0);
		
		#else
		throw std::runtime_error("XChaCha20 decryption not supported in this build");
		#endif
		
	} else {
		
		crypto::hasher checksum(header.password.type);
		checksum.update(header.password_salt.c_str(), header.password_salt.length());
		checksum.update(key.c_str(), key.length());
		return (checksum.finalize() == header.password);
		
	}
	
}

info::info() : codepage(0) { }
info::~info() { }

} // namespace setup
