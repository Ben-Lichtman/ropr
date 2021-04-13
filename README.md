# ropr

ropr is a blazing fast multithreaded ROP Gadget finder

### What is a ROP Gadget?

ROP (Return Oriented Programming) Gadgets are small snippets of a few assembly instructions typically ending in a `ret` instruction which already exist as executable code within each binary or library. These gadgets may be used for binary exploitation and to subvert vulnerable executables.

When the addresses of many ROP Gadgets are written into a buffer we have formed a ROP Chain. If an attacker can move the stack pointer into this ROP Chain then control can be completely transferred to the attacker.

Most executables contain enough gadgets to write a turing-complete ROP Chain. For those that don't, one can always use dynamic libraries contained in the same address-space such as libc once we know their addresses.

The beauty of using ROP Gadgets is that no new executable code needs to be written anywhere - an attacker may achieve their objective using only the code that already exists in the program.

### How do I use a ROP Gadget?

Typically the first requirement to use ROP Gadgets is to have a place to write your ROP Chain - this can be any readable buffer. Simply write the addresses of each gadget you would like to use into this buffer. If the buffer is too small there may not be enough room to write a long ROP Chain into and so an attacker should be careful to craft their ROP Chain to be efficient enough to fit into the space available.

The next requirement is to be able to control the stack - This can take the form of a stack overflow - which allows the ROP Chain to be written directly under the stack pointer, or a "stack pivot" - which is usually a single gadget which moves the stack pointer to the rest of the ROP Chain.

Once the stack pointer is at the start of your ROP Chain, the next `ret` instruction will trigger the gadgets to be excuted in sequence - each using the next as its return address on its own stack frame.

It is also possible to add function poitners into a ROP Chain - taking care that function arguments be supplied after the next element of the ROP Chain. This is typically combined with a "pop gadget", which pops the arguments off the stack in order to smoothly transition to the next gadget after the function arguments.

### How do I install ropr?

- Requires cargo (the rust build system)

Easy install:
```
cargo install ropr
```
the application will install to `~/.cargo/bin`

From source:
```
git clone https://github.com/Ben-Lichtman/ropr
cd ropr
cargo build --release
```
the resulting binary will be located in `target/release/ropr`

Alternatively:
```
git clone https://github.com/Ben-Lichtman/ropr
cd ropr
cargo install --path .
```
the application will install to `~/.cargo/bin`

### How do I use ropr?

```
USAGE:
    ropr [FLAGS] [OPTIONS] <binary>

FLAGS:
    -h, --help        Prints help information
    -c, --nocolour
    -j, --nojop
    -r, --norop
    -s, --nosys
    -V, --version     Prints version information

OPTIONS:
    -m, --max-instr <max-instr>     [default: 6]
    -R, --regex <regex>

ARGS:
    <binary>
```

- `nojop` - removes "JOP Gadgets" - these may have a controllable branch, call, etc. instead of a simple `ret` at the end
- `norop` - removes normal "ROP Gadgets"
- `nosys` - removes syscalls and other interrupts
- `max-instr`- maximum number of instructions in a gadget
- `regex` - Perform a regex search on the returned gadgets for easy filtering

For example if I was looking for a good stack-pivot I may choose to filter by the regex `^add esp, ...;`:

```
❯ ropr libc-2.32-5-x86_64.so -R "^add esp, ...;"
0x000e5e9b: add esp, eax; mov [r11+0x2C], r12d; pop r12; pop r13; pop r14; pop r15; ret;
0x0003eb41: add esp, edi; mov rdx, rbp; mov rsi, r12; mov rdi, r13; call rbx;
Found 2 gadgets
```

Now I have a good stack-pivot candidate at address `0x000e5e9b`
