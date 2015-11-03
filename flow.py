# test1.py
import gdb


from capstone import *
from capstone.x86 import *
class OpSrc(gdb.Command):
    def __init__(self):
        super (OpSrc, self).__init__("opsrc", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              True)
    def invoke(self, arg, from_tty):
        i = getinsn()
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if len(i.operands) == 2:
            src = i.operands[1]
            print(src.type)
            if src.type == X86_OP_REG:
                print("reg used %s \n" %i.reg_name(src.reg)),
            if src.type == X86_OP_MEM:
                if src.mem.index:
                    print("indexed src")
                    print(src.mem.scale)
                else:
                    print("mem used *(int*)($%s + %d)" % (i.reg_name(src.mem.base), src.mem.disp))
        else:
            print("unknown src")

OpSrc()

def isregdest(i, reg):
    print("isregdest")
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    if i.id in (X86_INS_PUSH, X86_INS_CALL, X86_INS_JMP):
        # these instruction don't write to a register
        pass
    elif i.id in (X86_INS_POP,):
        src = i.operands[0]
        if src.type == X86_OP_REG:
            print("reg used %s \n" %i.reg_name(src.reg))
            return reg == src.reg
    elif len(i.operands) == 2:
        print("two oper")
        src = i.operands[0]
        if src.type == X86_OP_REG:
            print("reg used %s \n" %i.reg_name(src.reg)),
            return reg == src.reg
    else:
        print("unknown src")

class RegDest(gdb.Command):
    def __init__(self):
        super (RegDest, self).__init__("regdest", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              True)
    def invoke(self, arg, from_tty):
        i = getinsn()
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if i.id in (X86_INS_PUSH, X86_INS_CALL, X86_INS_JMP):
            # these instruction don't write to a register
            pass
        elif i.id in (X86_INS_POP,):
            src = i.operands[0]
            if src.type == X86_OP_REG:
                print("reg used %s \n" %i.reg_name(src.reg)),
        elif len(i.operands) == 2:
            src = i.operands[0]
            if src.type == X86_OP_REG:
                print("reg used %s \n" %i.reg_name(src.reg)),
        else:
            print("unknown src")

RegDest()

def getinsn():
        length = gdb.selected_frame().architecture().disassemble(gdb.selected_frame().pc())[0]['length']
        CODE = gdb.selected_inferior().read_memory(gdb.selected_frame().pc(), length).tobytes()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        insns = list(md.disasm(CODE, 0x1000))
        assert(len(insns) == 1)
        return insns[0]

class RegWatch(gdb.Command):
    def __init__(self):
        super (RegWatch, self).__init__("regwatch", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              True)
    def invoke(self, arg, from_tty):
        i = getinsn()
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if len(i.operands) == 2:
            src = i.operands[1]
            print(src.type)
            if src.type == X86_OP_REG:
                print("target reg used %s \n" %i.reg_name(src.reg))
                target = src.reg
        else:
            print("unknown src")
        gdb.execute('rsi')
        i = getinsn()
        while not isregdest(i, target):
            gdb.execute('rsi')
            print("pc %x" % (gdb.selected_frame().pc()))
            i = getinsn()


RegWatch()

class Origin(gdb.Command):
    def __init__(self):
        super (Origin, self).__init__("origin", gdb.COMMAND_SUPPORT,
                                              gdb.COMPLETE_NONE,
                                              True)
    def invoke(self, arg, from_tty):
        i = getinsn()
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        if len(i.operands) == 2:
            src = i.operands[1]
            print(src.type)
            if src.type == X86_OP_REG:
                print("reg used %s \n" %i.reg_name(src.reg)),
            if src.type == X86_OP_MEM:
                if src.mem.index:
                    print("indexed src")
                    print(src.mem.scale)
                else:
                    location = ("*(int*)($%s + %d)" % (i.reg_name(src.mem.base), src.mem.disp))
                    print("mem used " + location)
                    gdb.Breakpoint(location, gdb.BP_WATCHPOINT, gdb.WP_WRITE, False, True)
                    gdb.execute("rc")
        else:
            print("unknown src")

Origin()

