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

#include "loader/offsets.hpp"

#include <cstring>
#include <limits>

#include <boost/cstdint.hpp>
#include <boost/static_assert.hpp>
#include <boost/range/size.hpp>

#include <stddef.h>

#include "crypto/crc32.hpp"
#include "loader/exereader.hpp"
#include "setup/version.hpp"
#include "util/load.hpp"
#include "util/log.hpp"
#include "util/output.hpp"

namespace loader {

namespace {

struct setup_loader_version {
	
	unsigned char magic[12];
	
	// Earliest known version with that ID
	setup::version_constant version;
	
};

const setup_loader_version known_setup_loader_versions[] = {
	{ { 'r', 'D', 'l', 'P', 't', 'S', 'V', 'x', 0x87, 'e', 'V', 'x' },    INNO_VERSION(1, 0,  9) },
	{ { 'r', 'D', 'l', 'P', 't', 'S', '0', '2', 0x87, 'e', 'V', 'x' },    INNO_VERSION(1, 2, 10) },
	{ { 'r', 'D', 'l', 'P', 't', 'S', '0', '4', 0x87, 'e', 'V', 'x' },    INNO_VERSION(4, 0,  0) },
	{ { 'r', 'D', 'l', 'P', 't', 'S', '0', '5', 0x87, 'e', 'V', 'x' },    INNO_VERSION(4, 0,  3) },
	{ { 'r', 'D', 'l', 'P', 't', 'S', '0', '6', 0x87, 'e', 'V', 'x' },    INNO_VERSION(4, 0, 10) },
	{ { 'r', 'D', 'l', 'P', 't', 'S', '0', '7', 0x87, 'e', 'V', 'x' },    INNO_VERSION(4, 1,  6) },
	{ { 'r', 'D', 'l', 'P', 't', 'S', 0xcd, 0xe6, 0xd7, '{', 0x0b, '*' }, INNO_VERSION(5, 1,  5) },
	{ { 'n', 'S', '5', 'W', '7', 'd', 'T', 0x83, 0xaa, 0x1b, 0x0f, 'j' }, INNO_VERSION(5, 1,  5) },
};

const int ResourceNameInstaller = 11111;

const boost::uint32_t SetupLoaderHeaderOffset = 0x30;
const boost::uint32_t SetupLoaderHeaderMagic = 0x6f6e6e49; // "Inno"

} // anonymous namespace

bool offsets::load_from_exe_file(std::istream & is) {
	
	is.seekg(SetupLoaderHeaderOffset);
	
	boost::uint32_t magic = util::load<boost::uint32_t>(is);
	if(is.fail() || magic != SetupLoaderHeaderMagic) {
		is.clear();
		return false;
	}
	
	debug("found Inno magic at " << print_hex(SetupLoaderHeaderOffset));
	
	found_magic = true;
	
	boost::uint32_t offset_table_offset = util::load<boost::uint32_t>(is);
	boost::uint32_t not_offset_table_offset = util::load<boost::uint32_t>(is);
	if(is.fail() || offset_table_offset != ~not_offset_table_offset) {
		is.clear();
		debug("header offset checksum: " << print_hex(not_offset_table_offset) << " != ~"
		                                 << print_hex(offset_table_offset));
		return false;
	}
	
	debug("found loader header at " << print_hex(offset_table_offset));
	
	return load_offsets_at(is, offset_table_offset, false);
}

bool offsets::load_from_exe_resource(std::istream & is) {

	exe_reader::resource resource = exe_reader::find_resource(is, ResourceNameInstaller);
	if(!resource) {
		is.clear();
		return false;
	}

	debug("found loader header resource at " << print_hex(resource.offset));

	found_magic = true;

	return load_offsets_at(is, resource.offset, false);
}

bool offsets::load_offsets_at(std::istream & is, boost::uint32_t pos, bool strict) {

	if(is.seekg(pos).fail()) {
		is.clear();
		debug("could not seek to loader header");
		return false;
	}

	char magic[12];
	if(is.read(magic, std::streamsize(sizeof(magic))).fail()) {
		is.clear();
		debug("could not read loader header magic");
		return false;
	}

	setup::version_constant version = 0;
	for(size_t i = 0; i < size_t(boost::size(known_setup_loader_versions)); i++) {
		BOOST_STATIC_ASSERT(sizeof(known_setup_loader_versions[i].magic) == sizeof(magic));
		if(!memcmp(magic, known_setup_loader_versions[i].magic, sizeof(magic))) {
			version = known_setup_loader_versions[i].version;
			debug("found loader header magic version " << setup::version(version));
			break;
		}
	}
	if(!version) {
		if(strict) {
			debug("unrecognized loader magic at " << print_hex(pos) << ", skipping");
			is.clear();
			return false;
		}
		log_warning << "Unexpected setup loader magic: " << print_hex(magic);
		version = std::numeric_limits<setup::version_constant>::max();
	}
	
	crypto::crc32 checksum;
	checksum.init();
	checksum.update(magic, sizeof(magic));
	
	if(version >= INNO_VERSION(5, 1,  5)) {
		boost::uint32_t revision = checksum.load<boost::uint32_t>(is);
		if(is.fail()) {
			is.clear();
			debug("could not read loader header revision");
			return false;
		} else if(revision != 1) {
			log_warning << "Unexpected setup loader revision: " << revision;
		}
	}
	
	(void)checksum.load<boost::uint32_t>(is);
	exe_offset = checksum.load<boost::uint32_t>(is);
	
	if(version >= INNO_VERSION(4, 1, 6)) {
		exe_compressed_size = 0;
	} else {
		exe_compressed_size = checksum.load<boost::uint32_t>(is);
	}
	
	exe_uncompressed_size = checksum.load<boost::uint32_t>(is);
	
	if(version >= INNO_VERSION(4, 0, 3)) {
		exe_checksum.type = crypto::CRC32;
		exe_checksum.crc32 = checksum.load<boost::uint32_t>(is);
	} else {
		exe_checksum.type = crypto::Adler32;
		exe_checksum.adler32 = checksum.load<boost::uint32_t>(is);
	}
	
	if(version >= INNO_VERSION(4, 0, 0) || version < INNO_VERSION(1, 2, 10)) {
		message_offset = 0;
	} else {
		message_offset = util::load<boost::uint32_t>(is);
	}
	
	header_offset = checksum.load<boost::uint32_t>(is);
	data_offset = checksum.load<boost::uint32_t>(is);
	
	if(is.fail()) {
		is.clear();
		debug("could not read loader header");
		return false;
	}
	
	if(version >= INNO_VERSION(4, 0, 10)) {
		boost::uint32_t expected = util::load<boost::uint32_t>(is);
		if(is.fail()) {
			is.clear();
			debug("could not read loader header checksum");
			return false;
		}
		if(checksum.finalize() != expected) {
			log_warning << "Setup loader checksum mismatch!";
		}
	}
	
	return true;
}

bool offsets::load_from_exe_scan(std::istream & is) {

	// Scan the file for a known loader magic (for very old versions without Inno pointer)
	static const char magic_prefix[] = { 'r', 'D', 'l', 'P', 't', 'S' };

	is.seekg(0, std::ios_base::end);
	std::streampos file_size = is.tellg();
	if(file_size < 12) {
		is.clear();
		return false;
	}

	is.seekg(0);

	char buf[8192];
	std::streampos pos = 0;
	while(pos < file_size) {
		std::streamsize to_read = std::min(std::streamsize(sizeof(buf)),
		                                   std::streamsize(file_size - pos));
		if(is.read(buf, to_read).fail()) {
			is.clear();
			return false;
		}
		std::streamsize nread = is.gcount();

		for(std::streamsize i = 0; i <= nread - 12; i++) {
			if(std::memcmp(buf + i, magic_prefix, sizeof(magic_prefix)) == 0) {
				boost::uint32_t candidate = boost::uint32_t(std::streamoff(pos) + i);
				debug("found potential loader magic at " << print_hex(candidate));
				if(load_offsets_at(is, candidate, true)) {
					return true;
				}
				// Seek back to continue scanning
				pos = std::streampos(std::streamoff(pos) + i + 1);
				is.seekg(pos);
				if(is.fail()) {
					is.clear();
					return false;
				}
				// Re-read buffer from this position
				to_read = std::min(std::streamsize(sizeof(buf)),
				                   std::streamsize(file_size - pos));
				if(to_read <= 0) {
					return false;
				}
				if(is.read(buf, to_read).fail()) {
					is.clear();
					return false;
				}
				nread = is.gcount();
				i = -1; // Will be incremented to 0
				continue;
			}
		}

		// Move back 11 bytes to catch magic split across buffer boundaries
		if(nread < 12) {
			break; // Not enough data remaining for a 12-byte magic match
		}
		pos += std::streamoff(nread - 11);
		is.seekg(pos);
	}

	is.clear();
	return false;
}

bool offsets::load_from_version_scan(std::istream & is) {

	// Scan for short legacy version strings: iXYZ-{16|32}\x1a (8 bytes)
	// Used by Inno Setup versions before 1.2.10

	is.seekg(0, std::ios_base::end);
	std::streampos file_size = is.tellg();
	if(file_size < 8) {
		is.clear();
		return false;
	}

	is.seekg(0);

	char buf[8192];
	std::streampos pos = 0;
	while(pos < file_size) {
		std::streamsize to_read = std::min(std::streamsize(sizeof(buf)),
		                                   std::streamsize(file_size - pos));
		if(is.read(buf, to_read).fail()) {
			is.clear();
			return false;
		}
		std::streamsize nread = is.gcount();

		for(std::streamsize i = 0; i <= nread - 8; i++) {
			if(buf[i] == 'i'
			   && (buf[i+4] == '-' || buf[i+4] == 'h')
			   && buf[i+7] == '\x1a'
			   && buf[i+1] >= '0' && buf[i+1] <= '9'
			   && buf[i+2] >= '0' && buf[i+2] <= '9'
			   && buf[i+3] >= '0' && buf[i+3] <= '9'
			   && ((buf[i+5] == '3' && buf[i+6] == '2')
			       || (buf[i+5] == '1' && buf[i+6] == '6'))) {

				boost::uint32_t candidate = boost::uint32_t(std::streamoff(pos) + i);
				debug("found short legacy version string at " << print_hex(candidate)
				      << ": " << std::string(buf + i, 7));

				// Verify that a valid block header follows the version string
				std::streampos saved_pos = is.tellg();
				is.seekg(candidate + 8); // seek past version string
				boost::uint32_t block_header[4];
				if(is.read(reinterpret_cast<char *>(block_header), 16).fail()) {
					is.clear();
					is.seekg(saved_pos);
					debug("could not read block header after version string, skipping");
					continue;
				}
				is.seekg(saved_pos);
				boost::uint32_t comp = util::little_endian::load<boost::uint32_t>(
				    reinterpret_cast<const char *>(&block_header[1]));
				boost::uint32_t uncomp = util::little_endian::load<boost::uint32_t>(
				    reinterpret_cast<const char *>(&block_header[2]));
				// For stored blocks, comp == 0xFFFFFFFF; otherwise comp <= uncomp * 2
				bool valid = false;
				if(comp == boost::uint32_t(-1)) {
					valid = (uncomp > 0 && uncomp < 0x10000000);
				} else {
					valid = (comp > 0 && uncomp > 0 && comp < 0x10000000
					         && uncomp < 0x10000000);
				}
				if(!valid) {
					debug("invalid block header after version string, skipping");
					continue;
				}

				found_magic = true;
				exe_compressed_size = exe_uncompressed_size = exe_offset = 0;
				message_offset = 0;
				header_offset = candidate;
				data_offset = 0;
				return true;
			}
		}

		// Move back 7 bytes to catch version string split across buffer boundaries
		if(nread < 8) {
			break;
		}
		pos += std::streamoff(nread - 7);
		is.seekg(pos);
	}

	is.clear();
	return false;
}

void offsets::load(std::istream & is) {

	found_magic = false;

	/*
	 * Try to load the offset table by following a pointer at a constant offset.
	 * This method of storing the offset table is used in versions before 5.1.5
	 */
	if(load_from_exe_file(is)) {
		return;
	}

	/*
	 * Try to load an offset table located in a PE/COFF (.exe) resource entry.
	 * This method of storing the offset table was introduced in version 5.1.5
	 */
	if(load_from_exe_resource(is)) {
		return;
	}

	/*
	 * Try to scan the file for a known loader magic.
	 * This is needed for very old versions that don't have the Inno pointer or PE resources.
	 */
	if(load_from_exe_scan(is)) {
		return;
	}

	/*
	 * Try to scan for a short legacy version string (iXYZ-{16|32}\x1a).
	 * This handles very old Inno Setup versions (pre-1.2.10) that may not have
	 * a recognizable loader magic or offset table.
	 */
	debug("trying version string scan");
	if(load_from_version_scan(is)) {
		return;
	}
	debug("version string scan failed");

	/*
	 * If no offset table has been found, this must be an external setup-0.bin file.
	 * In that case, the setup headers start at the beginning of the file.
	 */

	exe_compressed_size = exe_uncompressed_size = exe_offset = 0; // No embedded setup exe.

	message_offset = 0; // No embedded messages.

	header_offset = 0; // Whole file contains just the setup headers.

	data_offset = 0; // No embedded setup data.
}

} // namespace loader
