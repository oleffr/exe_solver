

from __future__ import print_function
from triton     import TritonContext, ARCH, MemoryAccess, CPUSIZE, Instruction, OPCODE, MODE , CALLBACK
import ctypes
import pyqbdi

import sys
import string
import random



#Адрес, с которого начитаем анализ
# addressStartAnalise = 0x1000  #crackme_xor
# addressStartAnalise = 0x410   #crackme1
addressStartAnalise = 0x1000    #crackme_memcpy
# addressStartAnalise = 0x146F

# Script options
DEBUG = True

# Memory mapping
BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_ALLOC = 0x30000000
BASE_STACK = 0x9ffffff0


# Signal handlers used by raise() and signal()
sigHandlers = dict()

# Allocation information used by malloc()
mallocCurrentAllocation = 0
mallocMaxAllocation     = 2048
mallocBase              = BASE_ALLOC
mallocChunkSize         = 0x00010000

globalSections=[]
procSize = None
addrProc = None

def getMemoryString(ctx, addr):
    s = str()
    index = 0

    while ctx.getConcreteMemoryValue(addr+index):
        c = chr(ctx.getConcreteMemoryValue(addr+index))
        if c not in string.printable: c = ""
        s += c
        index  += 1

    return s


def getStringPosition(text):
    formatters = ['%s','%d','%#02x', '%#x', '%02x', '%x', '%*s',    \
                  '%02X', '%lX', '%ld', '%08x', '%lu', '%u', '%c']

    text = text.replace("%s", " %s ").replace("%d", " %d ").replace("%#02x", " %#02x ")   \
           .replace("%#x", " %#x ").replace("%x", " %x ").replace("%02X", " %02X ")       \
           .replace("%c", " %c ").replace("%02x", " %02x ").replace("%ld", " %ld ")       \
           .replace("%*s", " %*s ").replace("%lX", " %lX").replace("%08x", " %08x ")      \
           .replace("%u", " %u ").replace("%lu", " %lu ")                                 \


    matches = [y for x in text.split() for y in formatters if y in x]
    indexes = [index for index, value in enumerate(matches) if value == '%s']
    return indexes


def getFormatString(ctx, addr):
    return getMemoryString(ctx, addr)                                               \
           .replace("%s", "{}").replace("%d", "{:d}").replace("%#02x", "{:#02x}")   \
           .replace("%#x", "{:#x}").replace("%x", "{:x}").replace("%02X", "{:02x}") \
           .replace("%c", "{:c}").replace("%02x", "{:02x}").replace("%ld", "{:d}")  \
           .replace("%*s", "").replace("%lX", "{:x}").replace("%08x", "{:08x}")     \
           .replace("%u", "{:d}").replace("%lu", "{:d}")                            \

def __GetLocalTime (ctx, addr):
    debug('__GetLocalTime hooked')
    global allInputs
    #Get arguments
    Buffer = ctx.getConcreteRegisterValue(ctx.registers.rсx)
    allInputs[countEmulation-1]+="GetLocalTime"
    ctx.symbolizeMemory(MemoryAccess(Buffer, CPUSIZE.DWORD))
    ctx.symbolizeMemory(MemoryAccess(Buffer+CPUSIZE.DWORD, CPUSIZE.DWORD))
    allInputs[countEmulation-1]+= str(ctx.getConcreteMemoryValue(Buffer, CPUSIZE.DWORD*2))
    return Buffer

def __GetSystemTimeAsFileTime  (ctx, addr):
    debug('__GetSystemTimeAsFileTime  hooked')
    global allInputs
    #Get arguments
    Buffer = ctx.getConcreteRegisterValue(ctx.registers.rсx)
    allInputs[countEmulation-1]+="GetSystemTimeAsFileTime "
    for addr in range(0,16):
        ctx.symbolizeMemory(MemoryAccess(Buffer+addr, CPUSIZE.BYTE))
        allInputs[countEmulation-1]+= chr(ctx.getConcreteMemoryValue(Buffer+addr))
    return Buffer


def __FindFirstFileW(ctx, addr):
    Name = ctx.getConcreteMemoryValue(ctx.getConcreteRegisterValue(ctx.registers.rcx),4)
    allOutput[countEmulation-1]+= "FindFirstFileW path: " +Name+ "\n"


def __GetModuleFileNameW(vm,ctx):
    debug('__GetModuleFileNameW hooked')
    FileName = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    Size = ctx.getConcreteRegisterValue(ctx.registers.r8b)
    allInputs[countEmulation-1]+= "GetModuleFileNameW whith name:" 
    for addr in range(0,20):
        ctx.symbolizeMemory(MemoryAccess(FileName+addr, CPUSIZE.BYTE))
        allInputs[countEmulation-1]+= chr(ctx.getConcreteMemoryValue(FileName+addr))
    print("__GetModuleFileNameW "+ str(FileName) + "  "+ str(Size))
    return FileName

def __SetPriorityClass(vm,ctx):
    allOutput[countEmulation-1]+= "SetPriorityClass" + "\n"

def __imp_CreateFileW(vm,ctx):
    debug('CreateFileW hooked')
    ctx.symbolizeRegister(ctx.registers.rax)
    return 1


def __RegOpenKeyExW(vm,ctx):
    debug('RegOpenKeyExW hooked')

    phkResult = ctx.getConcreteRegisterValue(ctx.registers.rax)
    for addr in range(0,8):
        ctx.symbolizeMemory(MemoryAccess(phkResult+addr, CPUSIZE.BYTE))
    allInputs[countEmulation-1]+= "RegOpenKeyExW   "
    return 0

def __RegQueryValueExW(vm,ctx):
    debug('RegQueryValueExW hooked')

    phkResult = ctx.getConcreteRegisterValue(ctx.registers.rax)
    for addr in range(0,8):
        ctx.symbolizeMemory(MemoryAccess(phkResult+addr, CPUSIZE.BYTE))
    allInputs[countEmulation-1]+= "RegQueryValueExW  " 
    return 0

def __RegGetValueW(vm,ctx):
    debug('RegGetValueW hooked')

    pvData = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rsp)+96)
    # ctx.symbolizeMemory(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp)+96, CPUSIZE.BYTE))

    # allInputs[countEmulation-1]+= chr(ctx.getConcreteMemoryValue(ctx.getConcreteRegisterValue(ctx.registers.rsp)+96))
    print(ctx.getConcreteMemoryValue(ctx.getConcreteRegisterValue(ctx.registers.rsp)+0x60))
    ctx.setConcreteMemoryValue(ctx.getConcreteRegisterValue(ctx.registers.rsp)+0x60, 42)
    pyqbdi.writeMemory(ctx.getConcreteRegisterValue(ctx.registers.rsp)+96, bytes('*', 'utf-8'))
    print(ctx.getConcreteMemoryValue(ctx.getConcreteRegisterValue(ctx.registers.rsp)+0x60))
    allInputs[countEmulation-1]+= "RegGetValueW  " + str(ctx.getConcreteMemoryValue(ctx.getConcreteRegisterValue(ctx.registers.rsp)+0x60))
    allOutput[countEmulation-1]+= "RegSetValueExW" + "YourValue"+"\n"
    
    
    return 0

def __ReadFile(vm, ctx):
    debug('__ReadFile hooked')
    global allInputs
    #Get arguments
    Buffer = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    Size = ctx.getConcreteRegisterValue(ctx.registers.r8b)
    allInputs[countEmulation-1]+="ReadFile"
    for addr in range(0,Size):
        ctx.symbolizeMemory(MemoryAccess(Buffer+addr, CPUSIZE.BYTE))
        allInputs[countEmulation-1]+= chr(ctx.getConcreteMemoryValue(Buffer+addr))
    return Buffer

# Simulate the puts() function
def __WriteFile(vm,ctx):
    debug('WriteFile hooked')
    

    # rdx = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    # print("0x{:x}: ".format(rcx))

    # runFunction(ctx, vm, "api-ms-win-crt-stdio-l1-1-0.dll", "puts")
    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdx))

    # print(pyqbdi.readMemory(rcx,len(arg1)))
    allOutput[countEmulation-1]+= "WriteFile hooked with:" + arg1+"\n"
    # sys.stdout.write(arg1 + '\n')
    # Return value
    return 

# Simulate the rand() function
def __rand(ctx):
    debug('rand hooked')
    # Return value
    return random.randrange(0xffffffff)


# Simulate the malloc() function
def __malloc(ctx):
    global mallocCurrentAllocation
    global mallocMaxAllocation
    global mallocBase
    global mallocChunkSize

    debug('malloc hooked')

    # Get arguments
    size = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    if size > mallocChunkSize:
        debug('malloc failed: size too big')
        sys.exit(-1)

    if mallocCurrentAllocation >= mallocMaxAllocation:
        debug('malloc failed: too many allocations done')
        sys.exit(-1)

    area = mallocBase + (mallocCurrentAllocation * mallocChunkSize)
    mallocCurrentAllocation += 1

    # Return value
    return area


# Simulate the signal() function
def __signal(ctx):
    debug('signal hooked')

    # Get arguments
    signal  = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    handler = ctx.getConcreteRegisterValue(ctx.registers.rsi)

    global sigHandlers
    sigHandlers.update({signal: handler})

    # Return value (void)
    return ctx.getConcreteRegisterValue(ctx.registers.rax)


# Simulate the raise() function
def __raise(ctx):
    debug('raise hooked')

    # Get arguments
    signal  = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    handler = sigHandlers[signal]

    ctx.processing(Instruction(b"\x6A\x00")) # push 0
    emulate(ctx, handler)

    # Return value
    return 0


# Simulate the strlen() function
def __strlen(ctx):
    debug('strlen hooked')

    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))

    # Return value
    return len(arg1)


# Simulate the strtoul() function
def __strtoul(ctx):
    debug('strtoul hooked')

    # Get arguments
    nptr   = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    endptr = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    base   = ctx.getConcreteRegisterValue(ctx.registers.rdx)

    # Return value
    return int(nptr, base)

# Simulate the printf() function
def __printf(ctx):
    debug('printf hooked')

    string_pos = getStringPosition(getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi)))

    # Get arguments
    arg1   = getFormatString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))
    arg2   = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3   = ctx.getConcreteRegisterValue(ctx.registers.rdx)
    arg4   = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    arg5   = ctx.getConcreteRegisterValue(ctx.registers.r8)
    arg6   = ctx.getConcreteRegisterValue(ctx.registers.r9)
    nbArgs = arg1.count("{")
    args   = [arg2, arg3, arg4, arg5, arg6][:nbArgs]
    rsp    = ctx.getConcreteRegisterValue(ctx.registers.rsp)

    if nbArgs > 5:
        for i in range(nbArgs - 5):
            args.append(ctx.getConcreteMemoryValue(MemoryAccess(rsp + CPUSIZE.QWORD * (i + 1), CPUSIZE.QWORD)))

    for i in string_pos:
        args[i] = getMemoryString(ctx, args[i])
    s = arg1.format(*args)
    sys.stdout.write(s)

    # Return value
    return len(s)


# Simulate the putchar() function
def __putchar(ctx):
    debug('putchar hooked')

    # Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    sys.stdout.write(chr(arg1) + '\n')

    # Return value
    return 2


# Simulate the puts() function
def __puts(vm,ctx):
    debug('puts hooked')
    

    rcx = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    print("0x{:x}: ".format(rcx))

    # runFunction(ctx, vm, "api-ms-win-crt-stdio-l1-1-0.dll", "puts")
    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rcx))

    print(pyqbdi.readMemory(rcx,len(arg1)))
    allOutput[countEmulation-1]+= arg1+"\n"
    # sys.stdout.write(arg1 + '\n')
    # Return value
    return len(arg1) + 1


def __libc_start_main(ctx):
    debug('__libc_start_main hooked')

    # Get arguments
    main = ctx.getConcreteRegisterValue(ctx.registers.rdi)

    # Push the return value to jump into the main() function
    ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)-CPUSIZE.QWORD)

    ret2main = MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD)
    ctx.setConcreteMemoryValue(ret2main, main)

    # Setup target argvs
    argvs = [sys.argv[1]] + sys.argv[2:]

    # Define argc / argv
    base  = BASE_ARGV
    addrs = list()

    index = 0
    for argv in argvs:
        addrs.append(base)
        ctx.setConcreteMemoryAreaValue(base, bytes(argv.encode('utf8')) + b'\x00')

        # Tainting argvs
        for i in range(len(argv)):
            ctx.taintMemory(base + i)

        base += len(argv)+1
        debug('argv[%d] = %s' %(index, argv))
        index += 1

    argc = len(argvs)
    argv = base
    for addr in addrs:
        ctx.setConcreteMemoryValue(MemoryAccess(base, CPUSIZE.QWORD), addr)
        base += CPUSIZE.QWORD

    ctx.setConcreteRegisterValue(ctx.registers.rdi, argc)
    ctx.setConcreteRegisterValue(ctx.registers.rsi, argv)

    return 0


# Simulate the atoi() function
def __atoi(ctx):
    debug('atoi hooked')

    # Get arguments
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.rdi))

    # Return value
    return int(arg1)


# Simulate the atol() function
def __atol(ctx):
    debug('atol hooked')

    # Get arguments
    arg1 = getMemoryString(ctx.getConcreteRegisterValue(ctx.registers.rdi))

    # Return value
    return int(arg1)


# Simulate the atoll() function
def __atoll(ctx):
    debug('atoll hooked')

    # Get arguments
    arg1 = getMemoryString(ctx.getConcreteRegisterValue(ctx.registers.rdi))

    # Return value
    return int(arg1)

def __memcpy(ctx):
    debug('memcpy hooked')

    #Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    arg2 = ctx.getConcreteRegisterValue(ctx.registers.rsi)
    arg3 = ctx.getConcreteRegisterValue(ctx.registers.rdx)

    for index in range(arg3):
        value = ctx.getConcreteMemoryValue(arg2 + index)
        ctx.setConcreteMemoryValue(arg1 + index, value)

    return arg1

def __strcat(ctx):
    debug('strcat hooked')

    #Get arguments
    arg1 = ctx.getConcreteRegisterValue(ctx.registers.rdi)
    arg2 = ctx.getConcreteRegisterValue(ctx.registers.rsi)

    src_length = len(getMemoryString(ctx, arg1))
    dest_length = len(getMemoryString(ctx, arg2))
    for index in range(dest_length):
        value = ctx.getConcreteMemoryValue(arg2 + index)
        ctx.setConcreteMemoryValue(arg1 + index + src_length, value)

    return arg1



def __acrt_iob_func(vm,ctx):
    debug('Emulating _acrt_iob_func')

    # Get the value from the argument (assuming it's in rcx)
    arg_value = ctx.getConcreteRegisterValue(ctx.registers.rcx)


    array_address = 0xD0F4A0

    # Calculate the offset (imul rax, 58h)
    offset = arg_value * 0x58

    # Add the offset to the array address (add rax, rcx)
    file_structure_address = array_address + offset

    return file_structure_address

def __stdio_common_vfprintf(vm,ctx):
    debug('Emulating __stdio_common_vfprintf')
        # Get arguments

    # runFunction(ctx, vm, "api-ms-win-crt-stdio-l1-1-0.dll", "__stdio_common_vfprintf")
    arg1 = getMemoryString(ctx, ctx.getConcreteRegisterValue(ctx.registers.r8))
    # allOutput[countEmulation-1]+= arg1+"\n"
    sys.stdout.write(arg1 + '\n')

    # Return value
    return len(arg1) + 1

def __gets_s(vm, ctx):
    debug('gets_s hooked')
    global allInputs
    #Get arguments
    Buffer = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    Size = ctx.getConcreteRegisterValue(ctx.registers.edx)
    for addr in range(0,Size):
        ctx.symbolizeMemory(MemoryAccess(Buffer+addr, CPUSIZE.BYTE))
        allInputs[countEmulation-1]+= chr(ctx.getConcreteMemoryValue(Buffer+addr))
    return Buffer

def __fgets(vm, ctx):
    debug('fgets_s hooked')
    global allInputs
    Buffer = ctx.getConcreteRegisterValue(ctx.registers.rcx)
    Size = ctx.getConcreteRegisterValue(ctx.registers.edx)
    for addr in range(0,Size):
        ctx.symbolizeMemory(MemoryAccess(Buffer+addr, CPUSIZE.BYTE))
        allInputs[countEmulation-1]+= chr(ctx.getConcreteMemoryValue(Buffer+addr))
    return Buffer



def get_seg(enum):
    import ctypes
    libc = ctypes.windll.kernel32
    syscall = libc.syscallc
    sys_arch_prctl = 158
    syscall.restype = ctypes.c_int
    syscall.argtypes = ctypes.c_long, ctypes.c_int, ctypes.POINTER(ctypes.c_ulong)
    v = ctypes.c_ulong()
    syscall(sys_arch_prctl, enum, ctypes.pointer(v))
    return v.value


# Triton callback. This callback is called when triton need to know
# the concrete value of memory cells. Synchronize memory cells between
# Triton and QBDI
def mem_read(tt, mem):
    addr = mem.getAddress()
    size = mem.getSize()

    qbdi_value   = pyqbdi.readMemory(addr, size)
    triton_value = tt.getConcreteMemoryAreaValue(addr, size)

    # If qbdi and triton mem cells are not equal, synch Triton with
    # the context of qbdi
    if qbdi_value != triton_value:
        print(F"[triton] Memory cells ({addr:x}:{size:d}) synchronization")
        tt.concretizeMemory(mem)
        tt.setConcreteMemoryAreaValue(addr, qbdi_value)

    return

# Synchronize registers between Triton and QBDI
def synch_regs_in_triton(tt, qbdi_gpr):
    values = {
        tt.registers.rax:    qbdi_gpr.rax,
        tt.registers.rbx:    qbdi_gpr.rbx,
        tt.registers.rcx:    qbdi_gpr.rcx,
        tt.registers.rdx:    qbdi_gpr.rdx,
        tt.registers.rdi:    qbdi_gpr.rdi,
        tt.registers.rsi:    qbdi_gpr.rsi,
        tt.registers.r8:     qbdi_gpr.r8,
        tt.registers.r9:     qbdi_gpr.r9,
        tt.registers.r10:    qbdi_gpr.r10,
        tt.registers.r11:    qbdi_gpr.r11,
        tt.registers.r12:    qbdi_gpr.r12,
        tt.registers.r13:    qbdi_gpr.r13,
        tt.registers.r14:    qbdi_gpr.r14,
        tt.registers.r15:    qbdi_gpr.r15,
        tt.registers.rbp:    qbdi_gpr.rbp,
        tt.registers.rsp:    qbdi_gpr.rsp,
        tt.registers.rip:    qbdi_gpr.rip,
        tt.registers.eflags: qbdi_gpr.eflags,
        tt.registers.fs:     qbdi_gpr.fs,
        tt.registers.gs:     qbdi_gpr.gs,
    }
    for k, v in values.items():
        qbdi_value   = v % (1 << k.getBitSize()) # ex. v % (1 << 64) to handle negative values with Python
        triton_value = tt.getConcreteRegisterValue(k)
        # If qbdi and triton register is not equal, synch Triton with
        # the context of qbdi
        if qbdi_value != triton_value:
            name = k.getName()
            print(F"[triton] Register ({name}: {qbdi_value:x} != {triton_value:x}) synchronization")
            tt.concretizeRegister(k)
            tt.setConcreteRegisterValue(k, qbdi_value)
    return



# QBDI callback
def cb(vm, gpr, fpr, tt):
    # Create a Triton instruction
    # print("test")
    # pdb.set_trace()
    instAnalysis = vm.getInstAnalysis()


    print("0x{:x}: {}".format(instAnalysis.address, instAnalysis.disassembly))
    
    inst = pyqbdi.readMemory(gpr.rip, instAnalysis.instSize)
    
    tt_inst = Instruction()   
    tt_inst.setOpcode(inst)
     # Setup Address
    tt_inst.setAddress(instAnalysis.address)                        

    tt_inst.setAddress(gpr.rip)



    # Process the Triton instruction
    synch_regs_in_triton(tt, gpr)
    
    # print(gpr)


    if tt_inst.getType() == OPCODE.X86.HLT:
            return


    # print(inst.hex())
    tt.processing(tt_inst)
    # print("test2")



    

    # Print its semantics
    # addr = tt_inst.getAddress()
    # disas = tt_inst.getDisassembly()


    return pyqbdi.CONTINUE


def postInst(vm, gpr, fpr, tt):
    # print("После инструкции")
    if hookingHandler(vm, tt):
        # print("hookingHandler")
        return pyqbdi.BREAK_TO_VM

    # instAnalysis = vm.getInstAnalysis()


    # print("0x{:x}: {}".format(instAnalysis.address, instAnalysis.disassembly))
    
    # inst = pyqbdi.readMemory(gpr.rip, instAnalysis.instSize)
    
    # tt_inst = Instruction()   
    # tt_inst.setOpcode(inst)
    #  # Setup Address
    # tt_inst.setAddress(instAnalysis.address)                              # Возникает ошибка. Стоит попробовать брать инструкцию из instAnalysis

    # tt_inst.setAddress(gpr.rip)



    # # Process the Triton instruction
    # synch_regs_in_triton(tt, gpr)
    
    # # print(gpr)

    # if tt_inst.getType() == OPCODE.X86.HLT:
    #         return
    # tt.processing(tt_inst)

    # if hookingHandler(vm, tt):
    #     return pyqbdi.BREAK_TO_VM
    return pyqbdi.CONTINUE



def insnCB(vm, gpr, fpr, tt):
    instAnalysis = vm.getInstAnalysis()


    print("0x{:x}: {}".format(instAnalysis.address, instAnalysis.disassembly))
    
    inst = pyqbdi.readMemory(gpr.rip, instAnalysis.instSize)
    
    tt_inst = Instruction()   
    tt_inst.setOpcode(inst)
     # Setup Address
    tt_inst.setAddress(instAnalysis.address)                              # Возникает ошибка. Стоит попробовать брать инструкцию из instAnalysis

    tt_inst.setAddress(gpr.rip)



    # Process the Triton instruction
    synch_regs_in_triton(tt, gpr)
    
    # print(gpr)

    if tt_inst.getType() == OPCODE.X86.HLT:
            return
    tt.processing(tt_inst)

    if hookingHandler(vm, tt):

        return pyqbdi.BREAK_TO_VM
    return pyqbdi.CONTINUE


def synch_regs(vm, tt):
    context = vm.getGPRState()

    context.rax = tt.getConcreteRegisterValue(tt.registers.rax)
    context.rbx = tt.getConcreteRegisterValue(tt.registers.rbx)
    context.rcx = tt.getConcreteRegisterValue(tt.registers.rcx)
    context.rdx = tt.getConcreteRegisterValue(tt.registers.rdx)
    context.rdi = tt.getConcreteRegisterValue(tt.registers.rdi)
    context.rsi = tt.getConcreteRegisterValue(tt.registers.rsi)
    context.r8 = tt.getConcreteRegisterValue(tt.registers.r8)
    context.r9 = tt.getConcreteRegisterValue(tt.registers.r9)
    context.r10 = tt.getConcreteRegisterValue(tt.registers.r10)
    context.r11 = tt.getConcreteRegisterValue(tt.registers.r11)
    context.r12 = tt.getConcreteRegisterValue(tt.registers.r12)
    context.r13 = tt.getConcreteRegisterValue(tt.registers.r13)
    context.r14 = tt.getConcreteRegisterValue(tt.registers.r14)
    context.r15 = tt.getConcreteRegisterValue(tt.registers.r15)
    context.rbp = tt.getConcreteRegisterValue(tt.registers.rbp)
    context.rsp = tt.getConcreteRegisterValue(tt.registers.rsp)
    context.rip = tt.getConcreteRegisterValue(tt.registers.rip)
    context.eflags = tt.getConcreteRegisterValue(tt.registers.eflags)
    print(context)
    # values = {
    #     tt.registers.rax:    qbdi_gpr.rax,
    #     tt.registers.rbx:    qbdi_gpr.rbx,
    #     tt.registers.rcx:    qbdi_gpr.rcx,
    #     tt.registers.rdx:    qbdi_gpr.rdx,
    #     tt.registers.rdi:    qbdi_gpr.rdi,
    #     tt.registers.rsi:    qbdi_gpr.rsi,
    #     tt.registers.r8:     qbdi_gpr.r8,
    #     tt.registers.r9:     qbdi_gpr.r9,
    #     tt.registers.r10:    qbdi_gpr.r10,
    #     tt.registers.r11:    qbdi_gpr.r11,
    #     tt.registers.r12:    qbdi_gpr.r12,
    #     tt.registers.r13:    qbdi_gpr.r13,
    #     tt.registers.r14:    qbdi_gpr.r14,
    #     tt.registers.r15:    qbdi_gpr.r15,
    #     tt.registers.rbp:    qbdi_gpr.rbp,
    #     tt.registers.rsp:    qbdi_gpr.rsp,
    #     tt.registers.rip:    qbdi_gpr.rip,
    #     tt.registers.eflags: qbdi_gpr.eflags,
    #     # tt.registers.fs:     get_seg(0x1003),
    #     # tt.registers.gs:     get_seg(0x1004),
    # }
    # for k, v in values.items():
    #     triton_value = tt.getConcreteRegisterValue(k)
    #     print("1 triton_value:",triton_value,"     qbdi_value:",v)
    #     # If qbdi and triton register is not equal, synch Triton with
    #     # the context of qbdi
    #     v = triton_value
    #     print("2 triton_value:",triton_value,"     qbdi_value:",v)
    #     # print(F"[triton] Register ({name}: {qbdi_value:x} != {triton_value:x}) synchronization")

    # print(qbdi_gpr)
    return

def synch_memory(tt, qbdi_gpr):
    global globalSections
    for addr,size in globalSections:
        value = tt.getConcreteMemoryAreaValue(addr,size)
        qbdi_gpr.writeMemory(addr, value)
    
    return






def runFunction(ctx,vm, dll, function):

    libmname = dll
    libm = ctypes.cdll.LoadLibrary(libmname)
    functionAtribute = getattr(libm,function)
    funcPtr = ctypes.cast(functionAtribute, ctypes.c_void_p).value

    
    synch_regs(ctx,vm)
    context = vm.getGPRState()
    
    # synch_memory(ctx,vm)

    # create stack
    addr = pyqbdi.allocateVirtualStack(context, context.rsp)
    assert addr is not None

    # instrument library and register memory access
    vm.addInstrumentedModuleFromAddr(funcPtr)
    vm.recordMemoryAccess(pyqbdi.MEMORY_READ_WRITE)

    # add callbacks on instructions
    

    pyqbdi.simulateCall(context, 0x42424242)
    success = vm.run(funcPtr, 0x42424242)

    # Retrieve output FPR state
    fpr = vm.getFPRState()

    print("Успех")
    # Cast long arg to double
 
    context = vm.getGPRState()
    print(context.rax)
    # cleanup
    pyqbdi.alignedFree(addr)











def getNewInput(ctx):
        # Set of new inputs
    inputs = list()

    # Get path constraints from the last execution
    pco = ctx.getPathConstraints()
        # Get the astContext
    astCtxt = ctx.getAstContext()

        # We start with any input. T (Top)
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())
        # Go through the path constraints
    for pc in pco:
        # If there is a condition

        if pc.isMultipleBranches():

            # Get all branches
            branches = pc.getBranchConstraints()
            for branch in branches:

                # Get the constraint of the branch which has been not taken
                if branch['isTaken'] == False:
                    # Ask for a model
                    models = ctx.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                    seed   = dict()
                    for k, v in list(models.items()):
                        # Get the symbolic variable assigned to the model
                        symVar = ctx.getSymbolicVariable(k)
                        # Save the new input as seed.
                        seed.update({symVar.getOrigin(): chr(v.getValue())})
                    if seed:
                        inputs.append(seed)

        # Update the previous constraints with true branch to keep a good path.
        previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPredicate()])

    # Clear the path constraints to be clean at the next execution.
    ctx.clearPathConstraints()

    return inputs


sincFunction = [
    # ['__libc_start_main', __libc_start_main,    None],
    # # ['__stdio_common_vfprintf',   __stdio_common_vfprintf,      None],
    # # ['__acrt_iob_func',   __acrt_iob_func,      None],
    # ['atoi',              __atoi,               None],
    # ['atol',              __atol,               None],
    # ['atoll',             __atoll,              None],
    # ['malloc',            __malloc,             None],
    # ['memcpy',            __memcpy,             None],
    # ['printf',            __printf,             None],
    # ['putchar',           __putchar,            None],
    # ['puts',              __puts,               None],
]


customRelocation = [
    # ['__libc_start_main', __libc_start_main,    None],
    # ['__stdio_common_vfprintf',   __stdio_common_vfprintf,      None],
    ['gets_s',            __gets_s,             None],
    ['fgets',            __fgets,             None],
    # ['CreateFileW',            __imp_CreateFileW,             None],
    ['ReadFile',            __ReadFile,             None],
    ['WriteFile',            __WriteFile,             None],
    # ['__acrt_iob_func',   __acrt_iob_func,      None],
    ['RegOpenKeyExW',            __RegOpenKeyExW,             None],
    ['RegQueryValueExW',         __RegQueryValueExW,          None],
    ['RegGetValueW',         __RegGetValueW,          None],
    ['GetModuleFileNameW',         __GetModuleFileNameW,          None],
    ['SetPriorityClass',         __SetPriorityClass,          None],
    
    
    # ['atoi',              __atoi,               None],
    # ['atol',              __atol,               None],
    # ['atoll',             __atoll,              None],
    # ['malloc',            __malloc,             None],
    # ['memcpy',            __memcpy,             None],
    # ['printf',            __printf,             None],
    # ['putchar',           __putchar,            None],
    ['puts',              __puts,               None],
    # ['raise',             __raise,              None],
    # ['rand',              __rand,               None],
    # ['signal',            __signal,             None],
    # ['strcat',            __strcat,             None],
    # ['strlen',            __strlen,             None],
    # ['strtoul',           __strtoul,            None],

]


def hookingHandler(vm,ctx):
    pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
    for rel in customRelocation:
        if rel[2] == pc:
            # Emulate the routine and the return value
            ret_value = rel[1](vm,ctx)
            if (ret_value != None):
                ctx.setConcreteRegisterValue(ctx.registers.rax, ret_value)
                print("RAX = " + str(ctx.getConcreteRegisterValue(ctx.registers.rax)))

            # Get the return address
            ret_addr = ctx.getConcreteMemoryValue(MemoryAccess(ctx.getConcreteRegisterValue(ctx.registers.rsp), CPUSIZE.QWORD))

            # print("ret_addr:",ret_addr)

            # Hijack RIP to skip the call
            ctx.setConcreteRegisterValue(ctx.registers.rip, ret_addr)

            # Restore RSP (simulate the ret)
            ctx.setConcreteRegisterValue(ctx.registers.rsp, ctx.getConcreteRegisterValue(ctx.registers.rsp)+CPUSIZE.QWORD)

            synch_regs(vm,ctx)
            return 1
    for rel in sincFunction:
        if rel[2] == pc:
            # Emulate the routine and the return value
            ret_value = rel[1](vm,ctx)    
    return 0


def checkMemory(ctx, pc):
    opcode = ctx.getConcreteMemoryAreaValue(pc, 1)
    instruction = Instruction(pc, opcode)
    print(opcode)
    print(instruction)
# Emulate the binary.

def emulate(vm, ctx, pc):
    count = 0
    while pc:
        # Fetch opcode
        opcode = ctx.getConcreteMemoryAreaValue(pc, 16)

        # Create the Triton instruction
        instruction = Instruction(pc, opcode)
        # Process
        print(instruction)
        ctx.processing(instruction)
        count += 1

        #print instruction
        if instruction.getType() == OPCODE.X86.HLT:
            break

        # Simulate routines
        hookingHandler(vm, ctx)

        # Next
        pc = ctx.getRegisterAst(ctx.registers.rip).evaluate()

    debug('Instruction executed: %d' %(count))
    return


def loadBinary(vm, ctx, path):
    import lief

    global sections , procSize, addrProc
    # Map the binary into the memory
    binary = lief.parse(path)
    sections = binary.sections


    lastSection = sections[len(sections)-1]

    procSize = lastSection.virtual_address+lastSection.virtual_address

    addrProc = pyqbdi.allocateMemory(procSize)


    print("0x{:x}: ".format(addrProc))





    for section in sections:
        vaddr = section.virtual_address+addrProc
        size = section.size
        print(section.name)
        debug('Loading virtusal 0x%06x - 0x%06x' % (vaddr-addrProc, vaddr + size-addrProc))
        debug('Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
        ctx.setConcreteMemoryAreaValue(vaddr, list(section.content))
        #print(bytes(section.content))
        print("\n")
        pyqbdi.writeMemory(vaddr, bytes(section.content))
        globalSections.append([vaddr,vaddr + size])

    vm.addInstrumentedRange(addrProc, addrProc + procSize)

    return binary



def makeRelocation(ctx, binary):
    # Setup plt

    global addrProc
    for pltIndex in range(len(customRelocation)):
        customRelocation[pltIndex][2] = BASE_PLT + pltIndex
        debug('Relocation %s  0x%06x' %(customRelocation[pltIndex][0], customRelocation[pltIndex][2]))


    # print(binary.symbols)

    import_table = binary.imports
    print("\n--IMPORT TABLE--\n")
    for imp in import_table:
        im =imp.entries
        print('\n%s: ' % imp.name)
        libm = ctypes.cdll.LoadLibrary(imp.name)
        for i in im:
            print('  %s' % i.name)

            functionAtribute = getattr(libm, i.name)
            funcPtr = ctypes.cast(functionAtribute, ctypes.c_void_p).value
            vm.addInstrumentedModuleFromAddr(funcPtr)

            bytes_representation = funcPtr.to_bytes(8, byteorder='little')
            # print("Test:",pyqbdi.readMemory(i.iat_address+addrProc,CPUSIZE.QWORD),"Test:" , bytes_representation)

            # print(bytes(ctx.getConcreteMemoryValue(MemoryAccess(i.iat_address+addrProc, CPUSIZE.QWORD))))
            # print("0x{:x}".format(i.iat_address+addrProc))
            pyqbdi.writeMemory(i.iat_address+addrProc,bytes_representation)
            

            for crel in range(len(customRelocation)):
                if i.name == customRelocation[crel][0]:
                    print("New relloc",i.name )
                    # debug('Hooking %s  0x%06x' %(i.name, i.iat_address+addrProc))
                    # debug('Hooking %s  0x%06x' %(i.name, crel[2]))
                    customRelocation[crel][2] = funcPtr

                    # ctx.setConcreteMemoryValue(MemoryAccess(i.iat_address+addrProc, CPUSIZE.QWORD), crel[2])
                    

                    break

            for crel in range(len(sincFunction)):
                if i.name == sincFunction[crel][0]:
                    print("New relloc",i.name )
                    # debug('Hooking %s  0x%06x' %(i.name, i.iat_address+addrProc))
                    # debug('Hooking %s  0x%06x' %(i.name, crel[2]))
                    sincFunction[crel][2] = funcPtr

                    # ctx.setConcreteMemoryValue(MemoryAccess(i.iat_address+addrProc, CPUSIZE.QWORD), crel[2])
                    

                    break

    return    



    relocations = [x for x in binary.pltgot_relocations]
    relocations.extend([x for x in binary.dynamic_relocations])

    # Perform our own relocations
    for rel in relocations:
        symbolName = rel.symbol.name
        symbolRelo = rel.address
        for crel in customRelocation:
            if symbolName == crel[0]:
                debug('Hooking %s' %(symbolName))
                ctx.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
                break
    return

# This function initializes the context memory.
def initContext(ctx):
    # Point RDI on our buffer. The address of our buffer is arbitrary. We just need
    # to point the RDI register on it as first argument of our targeted function.
    ctx.setConcreteRegisterValue(ctx.registers.rdi, 0x1000)

    # Setup stack on an abitrary address.
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x7fffffff)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x7fffffff)
    return

def debug(s):
    if DEBUG:
        print('[Triton] %s' %(s))
    return


def symbolizeInputs(ctx,seed):
    # Clean symbolic state
    ctx.concretizeAllRegister()
    ctx.concretizeAllMemory()
    for address, value in list(seed.items()):
        ctx.setConcreteMemoryValue(address, ord(value))
        pyqbdi.writeMemory(address, bytes(value, 'utf-8'))


    return

# if __name__ == '__main__':
#     # Set the architecture
#     ctx = TritonContext(ARCH.X86_64)

#     # Set a symbolic optimization mode
#     ctx.setMode(MODE.ALIGNED_MEMORY, True)


#     # Load the binary
#     binary = loadBinary(ctx, sys.argv[1])

#     # Perform our own relocations
#     makeRelocation(ctx, binary)

#     # Define a fake stack
#     ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
#     ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

#     # Let's emulate the binary from the entry point
#     debug('Starting emulation')
#     checkMemory(ctx,0x000410)
#     input()
#     emulate(ctx,  0x000410)
#     debug('Emulation done')
#     getNewInput(ctx)

#     sys.exit(0)

allInputs=[""]
allOutput=[""]
countEmulation=1





if __name__ == '__main__':

    ctx = TritonContext(ARCH.X86_64)

    # Symbolic optimization
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, mem_read)
    vm = pyqbdi.VM()
    


    # Load the binary
    binary = loadBinary(vm, ctx, sys.argv[1])
    # Perform our own relocations
    makeRelocation(ctx, binary)


    vm.addInstrumentedModuleFromAddr(addrProc)
    vm.recordMemoryAccess(pyqbdi.MEMORY_READ_WRITE)

    # 
    context = vm.getGPRState()
    

    addr = pyqbdi.allocateVirtualStack(context, 0x100000)

    print(context,"\n\n\n\n\n\n\n\n\n")

    print("Stack addr:", addr)
    assert addr is not None

    EntryPoint = addressStartAnalise+addrProc
    print(hex(binary.entrypoint))
    print(hex(EntryPoint))
    print("Test:",pyqbdi.readMemory(EntryPoint,16))
    input()

    vm.addCodeCB(pyqbdi.PREINST, cb, ctx)
    vm.addCodeCB(pyqbdi.POSTINST, postInst, ctx)

    pyqbdi.simulateCall(context, 0x000001)
    success = vm.run(addressStartAnalise+addrProc, 0x000001)

    newInputs = getNewInput(ctx)

    lastInput = list()
    worklist  = list()

    for inputs in newInputs:
        if inputs not in lastInput and inputs not in worklist:
            worklist += [dict(inputs)]

    print(success)
    # Define a fake stack
    ctx.setConcreteRegisterValue(ctx.registers.rbp, addr)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, addr)

    # We start the execution with a random value located at 0x1000.
    
    # worklist  = list([{0x1: '?'}])

    input()

    while worklist:
        # Take the first seed

        print(context,"\n\n\n\n\n\n\n\n\n")
        seed = worklist[0]

        print('Seed injected:', seed)

        allInputs.append('') 
        allOutput.append('') 
        countEmulation+=1

        # Symbolize inputs
        symbolizeInputs(ctx,seed)
        # Init context memory
        # initContext(ctx)
        # Emulate
        context.rsp =context.rbp
        pyqbdi.simulateCall(context, 0x000001)
        success = vm.run(addressStartAnalise+addrProc, 0x000001)
        # emulate(vm, ctx,  EntryPoint)

        lastInput += [dict(seed)]
        del worklist[0]



        newInputs = getNewInput(ctx)
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]
        # print("\n\n\n\n\n\n\n\n\n\n\n\n", worklist,"\n\n\n\n\n\n\n\n\n\n\n\n\n")

    if countEmulation == 1:
        print("Output:", allOutput[0],"\n")
        print("Input:", allInputs[0],"\n\n\n")
    for i in range(countEmulation-1):
        if( allOutput[i]):
            print("Output:", allOutput[i],"\n")
            print("Input:", allInputs[i],"\n\n\n")

    sys.exit(0)