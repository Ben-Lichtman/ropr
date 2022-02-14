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
    ropr [OPTIONS] <BINARY>

ARGS:
    <BINARY>    

OPTIONS:
    -b, --base-pivot               
    -c, --colour <COLOUR>          
    -h, --help                     Print help information
    -j, --nojop                    
    -m, --max-instr <MAX_INSTR>    [default: 6]
    -n, --noisy                    
    -p, --stack-pivot              
    -r, --norop                    
    -R, --regex <REGEX>            
        --raw <RAW>                
    -s, --nosys 
```

- `base-pivot` - Filters for gadgets which alter the base pointer
- `colour` - Forces output to be in colour or plain text
- `nojop` - Removes "JOP Gadgets" - these may have a controllable branch, call, etc. instead of a simple `ret` at the end
- `max-instr`- Maximum number of instructions in a gadget
- `noisy` - Includes potentially low-quality gadgets such as prefixes, conditional branches, and near branches (will find significantly more gadgets)
- `stack-pivot` - Filters for gadgets which alter the stack pointer
- `norop` - Removes normal "ROP Gadgets"
- `regex` - Perform a regex search on the returned gadgets for easy filtering
- `raw` - treats the input file as a blob of code
- `nosys` - Removes syscalls and other interrupts

For example if I was looking for a way to fill `rax` with a value from another register I may choose to filter by the regex `^mov eax, ...;`:

```
❯ ropr /usr/lib/libc.so.6 -R "^mov eax, ...;" > /dev/null

==> Found 197 gadgets in 0.118 seconds
```

Now I can add some filters to the command line for the highest quality results:

```
❯ ropr /usr/lib/libc.so.6 -m 2 -j -s -R "^mov eax, ...;"
0x000353e7: mov eax, eax; ret;
0x000788c8: mov eax, ecx; ret;
0x00052252: mov eax, edi; ret;
0x0003ae43: mov eax, edx; ret;
0x000353e6: mov eax, r8d; ret;
0x000788c7: mov eax, r9d; ret;

==> Found 6 gadgets in 0.046 seconds
```

Now I have a good `mov` gadget candidate at address `0x00052252`
