# Heathclift

Takes x86 targeted files that are readable by radare2 and generates a human readable LLVM IR
file. This file can be llvm-as'd into a bitcode version. The only thing it does is add 
function declarations and, in the case of non-imported functions, adds any call instructions
made in the function body. So, really this is only beneficial for doing call graph related
tasks. Further, all the lifted functions are (currently) assumed to be void-returning and
have no arguments. Whee. :-P This was all done for fun to learn a little bit about llvmlite
and be able to re-use some tools I have written in C++.

# Requirements

I have only tested this with LLVM 4.0, radare2 from their repo (sept 12, 2017), and llvmir 
from same date. You will also need r2pipe. For what it's worth, I had issues with turning off
demangling of function names, so I modified my local radare2 to have bin.demangle set to false
by default.

- [LLVM 4.0](http://releases.llvm.org/download.html)
- [llvmlite](https://github.com/numba/llvmlite) -- from September 12, 2017 (vague!)
- [radare2](https://github.com/radare/radare2) -- from September 12, 2017 (ditto!)
- [radare2-r2pipe](https://github.com/radare/radare2-r2pipe)

The file I changed in *radare2* to help with my demangle issue was:
```
$ cd radare2/libr/core
$ vi cconfig.c
....
change the line for bin.demangle from defaulting as true to default as false.
        SETPREF ("bin.demangle", "false", "Import demangled symbols from RBin");
...then build...
$
```


# Example usage

This takes the inputs of two shared libraries (x86) and generates foo.ll file. Then, taking
the human readable foo.ll file, use llvm-as to produce the binary bitcode IR version of it.
Then, use llvm-dis to dump the created bitcode version's IR back to the human readable form.
This shows that the generated foo.ll is usable with the 4.0 tools.

```
$ 
$ python heathclift.py --generate-llvm somelabel ../test/libjniPdfium.so ../test/libsqlcipher.so > foo.ll
$
$ llvm-as-4.0 -o foo_made.bc < foo.ll
$ llvm-dis-4.0 foo_made.ll
$ cat foo_made.ll
; ModuleID = 'foo_made.bc'
source_filename = "<stdin>"
target triple = "unknown-unknown-unknown"

define void @_ZNSt13bad_exceptionD2Ev() {
.2:
  call void @Unk_00006cc0()
  br label %.3

.3:                                               ; preds = %.2
  call void @_ZNSt9exceptionD1Ev()
  ret void
}

define void @CRYPTO_THREADID_get_callback() {
.2:
  call void @Unk_00117154()
  ret void
}

define void @POLICYINFO_free() {
.2:
  call void @Unk_0002be6b()
  br label %.3

.3:                                               ; preds = %.2
  call void @ASN1_item_free()
  ret void
}

define void @BIO_set_ex_data() {
.2:
  call void @Unk_0002be6b()
  br label %.3

.3:                                               ; preds = %.2
  call void @CRYPTO_set_ex_data()
  ret void
}

define void @_ZNSt15__exception_ptr13exception_ptrD2Ev() {
.2:
  call void @Unk_00006cc0()
  br label %.3

.3:                                               ; preds = %.2
....>snip<....
```

# Contact

Contact me (Andrew) if want to add more things. This was all done for fun and to have it
so that I did not need to re-write some tools I had written in C++ as well as learn the
basics of llvmlite.

[Andrew R. Reiter](arr@watson.org)

