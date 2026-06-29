/**
 *	Tempesta Client library API
 *
 * SPDX-FileCopyrightText: © 2026 Tempesta Technologies, Inc.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#ifdef __cplusplus
#include <cstddef>

extern "C" {
#endif

/**
 * Private binary data, necessary to pass between the library calls.
 */
struct TlProgPrvt;

/**
 * Text representation of parsed configuration plus binary data, opaque for users.
 * This data structure is supposed to be used by a client code (e.g. tfw CLI or
 * imagine a Python web app) as a main hadler passed between the library calls,
 * which still can provide some useful for the client code information.
 *
 * @tfw_conf		- Tempesta FW configuration, for now just passed to all the
 *			  instances in a minified representation.
 * @tfw_conf_len	- length of minified Tempesta FW configuration.
 * @tl_prog_txt		- just extracted TL program for following passing to the
 *			  compiler. Not minified to make compiler messages informative.
 * @tl_prog_txt_len	- length of the TL program.
 * @prvt		- opaque binary data invisible for the client code.
 *			  It's in the C part to keep the data structure size the same.
 */
typedef struct TlProgConf {
	char			*tfw_conf;
	size_t			tfw_conf_len;
	char			*tl_prog_txt;
	size_t			tl_prog_txt_len;
	struct TlProgPrvt	*prvt;

#ifdef __cplusplus
	TlProgConf(const TlProgConf &) =delete;
	TlProgConf &operator=(const TlProgConf &) =delete;
	TlProgConf();
	~TlProgConf();
#endif
} TlProgConf;

/**
 * Switch on/off debug printing.
 */
void tcl_debug(bool enable);

/**
 * Get an error description string.
 * The function should be used only if an error occured, otherwise it returns
 * a garbage or a previous error message.
 */
const char *tcl_error_str();

void tcl_prog_conf_init(TlProgConf *conf);

/**
 * Parse configuration text, which could be a file or command line argument content.
 * The text may contain one or many lines of TL, Tempesta FW or xFW configuration
 * intermixed with comments.
 * On success allocates and returns parsed sections without comments, but does not
 * parse section internals such as `tfw` or `tl` contents.
 */
TlProgConf *tcl_parse_full_conf(const char *text, size_t len);

/**
 * Parse configuration patch, which could be a file or command line argument content.
 * The text may contain one or many lines of TL, Tempesta FW or xFW configuration
 * intermixed with comments.
 * On success allocates and returns parsed sections without comments, but does not
 * parse section internals such as `tfw` or `tl` contents.
 */
TlProgConf *tcl_parse_patch_conf(const char *text, size_t len);

/**
 * Parse only TL section.
 */
TlProgConf *tcl_parse_tl(const char *text, size_t len);

/**
 * Frees configuration, allocated by tcl_parse_*().
 */
void tcl_free_conf(TlProgConf *conf);

/**
 * Call TL compiler to compile a program @text.
 */
int tcl_tl_compile(TlProgConf *conf);

#ifdef __cplusplus
}
#endif
