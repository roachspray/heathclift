#
# Heath's (weak) Call Lifter (but we're not really sure who Heath is!)
# heathclift.py
#
# Blindly lift calls of functions to LLVM IR.
# I say "blindly" because the code assumes all
# functions are returning void and have no arguments.
# Also, this does not deal with call <reg> or 
# call dword [ <reg> [+ off] ] cases. So, yea.
#
# "THE BEER-WARE LICENSE" (Revision 42):
# <arr@watson.org> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Andrew R. Reiter
#

import sys
import r2pipe
import llvmlite.ir as ll

def simple_mode(sargv):
    cmd = sargv[1]
    file = sargv[2]

    if cmd == "--internal-functions":
        r2 = r2pipe.open(file, flags=["-a", "x86"])
        r2.cmd("aa")
        dump_internal_functions(r2)
    elif cmd == "--external-functions":
        r2 = r2pipe.open(file, flags=["-a", "x86"])
        r2.cmd("aa")
        dump_external_functions(r2)
    else:
        return

def dump_internal_functions(r2):
    fn_list = r2.cmdj("aflj")
    for fne in fn_list:
        name = fne["name"]
        if name.startswith("sym.imp.") == True:
            continue 
        if name.startswith("sym.") == True:
            name = name.replace("sym.", "")
        if name.startswith("fcn.") == True:
            name = name.replace("fcn.", "unk_")
        print "{}".format(name)

def dump_external_functions(r2):
    fn_list = r2.cmdj("aflj")
    for fne in fn_list:
        name = fne["name"]
        if name.startswith("sym.imp.") == True:
            print "{}".format(name.replace("sym.imp.", ""))

def generate_llvm(module_name, libs):
    # key: function name (including sym.*, fcn.)
    # value: (Function, opcodes)

    added_functions = {} 
    real_name = []
    for lib in libs:
        r2 = r2pipe.open(lib, flags=["-a", "x86"])
        r2.cmd("aa")
        fn_list = r2.cmdj("aflj")
        for fne in fn_list:
            name = fne["name"]
            is_imp = name.startswith("sym.imp.")
            rname = name.replace("sym.imp.", "")
            rname = rname.replace("sym.", "")
            rname = rname.replace("fcn.", "Unk_")

            if is_imp == True:
                # Avoid clobbering from other library file
                if rname not in added_functions.keys():
                    added_functions[rname] = (None, None)
                continue

            # These will be (name, offset) where /offset/ is
            # is offset from start of the function named /name/
            # However, I believe we no longer need to do the st
            calledFns = []
            r2.cmd("af@{0}".format(name))

            # Use the original name found from aflj command
            dis = r2.cmdj("pdfj@{0}".format(name))
            if dis is None:
                added_functions[rname] = (None, None)
                continue
            offset = 0
            for op in dis["ops"]:
                if "bytes" not in op.keys():
                    continue
                inst = op["opcode"]
                if inst.startswith("call") == True:
                    call_inst = inst.split(" ")
                    # call dword [eax + ..]
                    if len(call_inst) > 2:
                        offset = offset + op["size"]  
                        continue
                    if call_inst[1].startswith("0x") == True:
                        offset = offset + op["size"]  
                        continue
                    if call_inst[1] in ["eax", "ebx", "ecx", "edx"]:
                        offset = offset + op["size"]  
                        continue
                    targFn = call_inst[1].replace("sym.imp.", "")
                    targFn = targFn.replace("sym.", "")
                    targFn = targFn.replace("fcn.", "Unk_")
                    calledFns.append((targFn, offset))
                    offset = offset + op["size"]  
                else:
                    offset = offset + op["size"]  
            added_functions[rname] = (None, calledFns)

    module = ll.Module(name=module_name)
    fntype = ll.FunctionType(ll.VoidType(), [])
    seriously_added = [] 
    for oname in added_functions.keys():
        seriously_added.append(oname)
        tpl = added_functions[oname]
        fn = ll.Function(module, fntype, name=oname)
        added_functions[oname] = (fn, tpl[1])

    for oname in added_functions.keys():
        func = added_functions[oname][0]
        if func is None:
           continue

        # called_functions is [(name, offset)]
        called_functions = added_functions[oname][1]
        if called_functions == None or len(called_functions) == 0:
            continue

        builder = ll.IRBuilder()
        k = 0
        bb_entry = func.append_basic_block()
        called_functions = [x for x in called_functions  \
          if x[0] in added_functions.keys()]
        offset = []

        # ct is (called_fn_name, offset)
        for ct in called_functions:
            callee_name = ct[0]
            off_val = ct[1]
            k += 1
            builder.position_at_end(bb_entry)
            callee_fn = added_functions[callee_name][0]

            # Converted to string; this is done regardless of type underneath
            offset.append(str(off_val))

            # Insert CallInst(Function *, args[], name)
            builder.call(callee_fn, [], callee_name) 
            if k < len(called_functions):
                new_bb = func.append_basic_block()
                builder.branch(new_bb)
                bb_entry = new_bb
            else:
                builder.ret_void()

        # add list of offsets for each function called in /oname/
        # as metadata. retrieved programmatically
        module.add_named_metadata("calloffsets_{}".format(oname), offset)
        func.blocks = [ x for x in func.blocks if len(x.instructions) > 0 ]
    print(module)

def main():
    if len(sys.argv) == 3:
        simple_mode(sys.argv)
    elif len(sys.argv) >= 4 and sys.argv[1] == "--generate-llvm":
        # module name, object files merging
        generate_llvm(sys.argv[2], sys.argv[3:])

    sys.exit(0)

if __name__ == '__main__':
    main()
