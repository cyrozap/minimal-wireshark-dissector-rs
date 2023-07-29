# minimal-wireshark-dissector-rs

A minimal Wireshark dissector, written purely in Rust (no C whatsoever).


## What is this?

This is a pure-Rust implementation of a Wireshark dissector plugin. The plugin
will automatically register the dissector and add it to the wiretap
encapsulation table for the "USER 0" encapsulation type.


## How do I try this?

1. `cargo build`
2. `cp target/debug/libminimal.so ~/.local/lib/wireshark/plugins/4.0/epan/`
3. `wireshark resources/minimal.pcapng`


## Why does this exist?

I wanted to try writing a Wireshark dissector in Rust, without any dependencies
or auto-generated bindings.


## Should I use this as the base for my Wireshark dissector plugin?

Probably not, for a number of reasons:

- This code is very close to the absolute bare minimum of a dissector, and most
  of the code needed to make a _useful_ dissector has not been included.
- Wireshark expects dissectors to call into libwireshark a lot, so quite a lot
  of code is needed to translate from C to Rust and back again.
- Wireshark requires a lot of manual registration and pre-definition of fields,
  which requires a lot of boilerplate code and calling into a bunch of C
  functions, and this minimal example does not include any helper functions to
  do this.
- Because of how much work is done in libwireshark (which is C code), many of
  the benefits that Rust would otherwise bring to protocol parsing are lost.
- There are better options available that expose a more Rust-y API, like
  [iwanders/wireshark\_dissector\_rs][wireshark_dissector_rs]

I wrote a much more complicated dissector based on this minimal example, and it
turned into a spaghetti nightmare due to all the boilerplate and C-to-Rust-to-C
conversions. Because of this experience, I strongly suggest you either write
your dissector in C (or Lua, if you don't need the speed or the extra features
that a C dissector would provide) or write it in Rust using
[iwanders/wireshark\_dissector\_rs][wireshark_dissector_rs].


[wireshark_dissector_rs]: https://github.com/iwanders/wireshark_dissector_rs
