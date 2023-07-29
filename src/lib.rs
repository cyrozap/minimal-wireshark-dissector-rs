// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  src/lib.rs - Minimal dissector plugin example for Wireshark.
 *  Copyright (C) 2023  Forest Crossman <cyrozap@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CString};

#[repr(C)]
struct ProtoPlugin {
    register_protoinfo: extern "C" fn(),
    register_handoff: extern "C" fn(),
}

#[link(name = "wireshark")]
extern "C" {
    fn create_dissector_handle(
        dissector: extern "C" fn(
            *const c_void,
            *const c_void,
            *const c_void,
            *const c_void,
        ) -> c_int,
        proto: c_int,
    ) -> *const c_void;

    fn dissector_add_uint(name: *const c_char, pattern: u32, handle: *const c_void);

    fn proto_register_plugin(plugin: *const ProtoPlugin);

    fn proto_register_protocol(
        name: *const c_char,
        short_name: *const c_char,
        filter_name: *const c_char,
    ) -> c_int;

    fn proto_tree_add_item(
        tree: *const c_void,
        hfindex: c_int,
        tvb: *const c_void,
        start: c_int,
        length: c_int,
        encoding: c_uint,
    ) -> *const c_void;

    fn tvb_captured_length(tvb: *const c_void) -> c_int;
}

static mut PROTO_MINIMAL: c_int = -1;

extern "C" fn dissect_minimal(
    tvb: *const c_void,
    _pinfo: *const c_void,
    tree: *const c_void,
    _data: *const c_void,
) -> c_int {
    println!("Dissector called!");

    let proto_minimal = unsafe { PROTO_MINIMAL };

    unsafe {
        proto_tree_add_item(tree, proto_minimal, tvb, 0, 1, 0 /* ENC_NA */);
    }

    unsafe { tvb_captured_length(tvb) }
}

extern "C" fn proto_register_minimal() {
    unsafe {
        PROTO_MINIMAL = proto_register_protocol(
            CString::new("Minimal Dissector Example")
                .unwrap()
                .into_raw()
                .cast_const(),
            CString::new("Minimal").unwrap().into_raw().cast_const(),
            CString::new("minimal").unwrap().into_raw().cast_const(),
        );
    }

    println!("Protocol registered!");
}

extern "C" fn proto_reg_handoff_minimal() {
    let minimal_handle = unsafe { create_dissector_handle(dissect_minimal, PROTO_MINIMAL) };

    unsafe {
        dissector_add_uint(
            CString::new("wtap_encap").unwrap().into_raw().cast_const(),
            45, // NOTE: WTAP_ENCAP_USER0 is defined in wiretap/wtap.h and is NOT the DLT number.
            minimal_handle,
        );
    }

    println!("Protocol handoff!");
}

static PLUGIN: ProtoPlugin = ProtoPlugin {
    register_protoinfo: proto_register_minimal,
    register_handoff: proto_reg_handoff_minimal,
};

#[no_mangle]
pub extern "C" fn plugin_register() {
    unsafe {
        proto_register_plugin(&PLUGIN);
    }

    println!("Plugin registered!");
}

#[no_mangle]
pub static plugin_version: [c_uchar; 6] = *b"0.1.0\0";

#[no_mangle]
pub static plugin_want_major: c_int = 4;

#[no_mangle]
pub static plugin_want_minor: c_int = 0;
