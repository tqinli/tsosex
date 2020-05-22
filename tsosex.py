import lldb
import re
import json
import pickle
import socket
import struct
import sys
from shlex import split

null_addr = '0000000000000000'
default_name = 'tsosex'
tmp_file = '/tmp/%s.txt' % default_name
process = lldb.debugger.GetSelectedTarget().GetProcess()
process_name = process.GetProcessInfo().GetName()

'''
object type
    MT, OBJ, STRUCT, ARRAY
''' and None
objmap = dict()
typemap = dict()
cmdhist = set()
tmpobjmap = dict()

typeblacklist = [
    'System.Boolean[]',
    'System.Int32[]',
    'System.Int64[]',
    'System.Byte[]',
    'System.Char[]',
    'System.IntPtr[]',
    'System.Single[]',
    'System.Double[]',
]

def inv_dict(**args):
    inv = {v: k for k, v in args.items()}
    return inv

# https://github.com/dotnet/corefx/blob/release/3.0/src/System.Net.Sockets/src/System/Net/Sockets/SocketAsyncContext.Unix.cs#L693
enumSockAsyncOpQueueState = {
    0: 'Ready',  # Indicates that data MAY be available on the socket. Queue must be empty.
    1: 'Waiting', # Indicates that data is definitely not available on the socket. Queue must not be empty.
    2: 'Processing', # Indicates that a thread pool item has been scheduled (and may be executing) to process the IO operations in the queue. Queue must not be empty.
    3: 'Stopped', # Indicates that the queue has been stopped because the socket has been closed. Queue must be empty.
}

# https://github.com/dotnet/corefx/blob/release/3.0/src/System.Net.Primitives/src/System/Net/Sockets/SocketError.cs#L10 
enumSocketError = inv_dict(
    Success = 0,
    SocketError = (-1),
    Interrupted = (10000 + 4),
    AccessDenied = (10000 + 13),
    Fault = (10000 + 14),
    InvalidArgument = (10000 + 22),
    TooManyOpenSockets = (10000 + 24),

    # Windows Sockets definitions of regular Berkeley error constants
    WouldBlock = (10000 + 35),
    InProgress = (10000 + 36),
    AlreadyInProgress = (10000 + 37),
    NotSocket = (10000 + 38),
    DestinationAddressRequired = (10000 + 39),
    MessageSize = (10000 + 40),
    ProtocolType = (10000 + 41),
    ProtocolOption = (10000 + 42),
    ProtocolNotSupported = (10000 + 43),
    SocketNotSupported = (10000 + 44),
    OperationNotSupported = (10000 + 45),
    ProtocolFamilyNotSupported = (10000 + 46),
    AddressFamilyNotSupported = (10000 + 47),
    AddressAlreadyInUse = (10000 + 48),
    AddressNotAvailable = (10000 + 49),
    NetworkDown = (10000 + 50),
    NetworkUnreachable = (10000 + 51),
    NetworkReset = (10000 + 52),
    ConnectionAborted = (10000 + 53),
    ConnectionReset = (10000 + 54),
    NoBufferSpaceAvailable = (10000 + 55),
    IsConnected = (10000 + 56),
    NotConnected = (10000 + 57),
    Shutdown = (10000 + 58),
    TimedOut = (10000 + 60),
    ConnectionRefused = (10000 + 61),
    HostDown = (10000 + 64),
    HostUnreachable = (10000 + 65),
    ProcessLimit = (10000 + 67),

    # Extended Windows Sockets error constant definitions
    SystemNotReady = (10000 + 91),
    VersionNotSupported = (10000 + 92),
    NotInitialized = (10000 + 93),
    Disconnecting = (10000 + 101),
    TypeNotFound = (10000 + 109),
    HostNotFound = (10000 + 1001),
    TryAgain = (10000 + 1002),
    NoRecovery = (10000 + 1003),
    NoData = (10000 + 1004),

    # OS dependent errors
    IOPending = 997,
    OperationAborted = 0x3E3,
)

is_debug = False
def dprint(msg):
    if is_debug:
        print(msg)

def tset_debug(debugger, command, result, args):
    global is_debug
    if 0 == len(command):
        command = 1
    result.AppendMessage('DebugMode was set to: %s' % is_debug)
    is_debug = bool(int(command))
    result.AppendMessage('DebugMode is now: %s (%s)' % (is_debug, command))

def copystate(mod):
    global objmap, typemap, cmdhist
    objmap = mod.objmap
    typemap = mod.typemap
    cmdhist = mod.cmdhist

def tsave(debugger, command, result, args):
    global process, process_name
    if not process or not process_name:
        process = lldb.debugger.GetSelectedTarget().GetProcess()
        process_name = process.GetProcessInfo().GetName()

    fn = '%s.pdat' % process_name
    fp = open(fn, "wb")
    pickle.dump(objmap, fp)
    result.AppendMessage('objmap saved (#%d)' % len(objmap))
    pickle.dump(typemap, fp)
    result.AppendMessage('typemap saved (#%d)' % len(typemap))
    pickle.dump(cmdhist, fp)
    result.AppendMessage('cmdhist saved (#%d)' % len(cmdhist))
    fp.close()

def tload(debugger, command, result, args):
    global process, process_name
    if not process or not process_name:
        process = lldb.debugger.GetSelectedTarget().GetProcess()
        process_name = process.GetProcessInfo().GetName()

    global objmap, typemap, cmdhist
    fn = '%s.pdat' % process_name
    fp = open(fn, "rb")
    objmap = pickle.load(fp)
    result.AppendMessage('objmap loaded (#%d)' % len(objmap))
    typemap = pickle.load(fp)
    result.AppendMessage('typemap loaded (#%d)' % len(typemap))
    cmdhist = pickle.load(fp)
    result.AppendMessage('cmdhist loaded (#%d)' % len(cmdhist))
    fp.close()

def inc_key(dic, key):
    if key in dic:
        dic[key] += 1
    else:
        dic[key] = 1

def objstat(mincount = 20):
    tcount = dict()
    ccount = dict()

    for o in objmap.values():
        t = o['__Type']
        inc_key(tcount, t)
        c = o['__ClassName']
        inc_key(ccount, c)

    for k, v in tcount.items():
        if v > mincount:
            dprint('TYPE %s object count %d' % (k, v))
    for k, v in ccount.items():
        if v > mincount:
            dprint('CLASS %s object count %d' % (k, v))


def get_cmd_output_res(debugger, command):
    dprint('... %s ...' % command)
    ci = debugger.GetCommandInterpreter()
    res = lldb.SBCommandReturnObject()
    ci.HandleCommand(command, res)
    return res

def get_cmd_output(debugger, command):
    return get_cmd_output_res(debugger, command).GetOutput()

'''

/// SOS command output format

(lldb) dumpheap -stat
Statistics:
              MT    Count    TotalSize Class Name
00007fb5ddbef5b0        1           24 System.Threading.Tasks.ThreadPoolTaskScheduler
...
Total 13945 objects

''' and None

def tinit(debugger, command, result, args):
    cmd = 'dumpheap -stat'
    if cmd in cmdhist:
        result.AppendMessage('HeapStat already initiated')
        return
    cmdhist.add(cmd)

    hs = get_cmd_output(debugger, cmd)
    lines = filter(None, hs.split('\n'))
    if lines[0] != 'Statistics:':
        result.SetError('Unexpected output: %s' % lines[0])
        return
    if lines[1] != '              MT    Count    TotalSize Class Name':
        result.SetError('Unexpected output: %s' % lines[1])
        return
    if not lines[-1].startswith('Total ') or not lines[-1].endswith(' objects'):
        result.SetError('Unexpected output: %s' % lines[-1])
        return

    cnt = 0
    for l in lines[2:-1]:
        ts = filter(None, l.split(' '))
        mt = ts[0]

        pbag = dict(__Type = 'MT', __Address = ts[0], __Count = int(ts[1]), __TotalSize = int(ts[2]), __ClassName = ts[3])
        load_mt_helper(debugger, mt, pbag)
        cnt += 1

    result.AppendMessage('Total %d MT found' % cnt)

'''

/// SOS command output format

(lldb) dumpmt 00007fb5ddbe83d0
EEClass:         00007FB5DDBF4F28
Module:          00007FB5DD9B6DD0
Name:            System.Net.Sockets.SocketAsyncContext+AcceptOperation
mdToken:         000000000200007B
File:            /usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.3/System.Net.Sockets.dll
BaseSize:        0x58
ComponentSize:   0x0
Slots in VTable: 11
Number of IFaces in IFaceMap: 1

''' and None

def load_mt_helper(debugger, mt, pbag = None):
    if not is_valid_addr(mt):
        return None
    if mt in objmap:
        return objmap[mt]

    hs = get_cmd_output(debugger, 'dumpmt %s' % mt)
    lines = filter(None, hs.split('\n'))
    if null_addr == mt:
        return pbag
    if 'Free MethodTable' == lines[0]:
        return pbag
    if not lines[0].startswith('EEClass:'):
        dprint('Unexpected output %s for MT %s' % (lines[0], mt))
        return pbag
    
    if not pbag:
        pbag = dict(__Type = 'MT', __Address = mt)
    
    for l in lines:
        if l.startswith('ContainsPointers '):
            # for some stupid reason, this column comes with a different format
            k, v = map(lambda s: s.strip().replace(' ', ''), l.split(' '))
            continue
        try:
            k, v = map(lambda s: s.strip().replace(' ', ''), l.split(':'))
            pbag[k] = v
        except:
            dprint("Unable to parse for MT %s: %s" % (mt, l))
            
    
    pbag['__EEClass'] = pbag['EEClass'].lower()
    pbag['__ClassName'] = pbag['Name']

    # store MT to objmap
    objmap[mt] = pbag
    typemap[pbag['__ClassName']] = pbag
    return pbag

'''

/// SOS command output format

(lldb) dumpheap -mt 00007fb5dd9b9d60
         Address               MT     Size
00007fb5b801aa00 00007fb5dd9b9d60       96
00007fb5b801f748 00007fb5dd9b9d60       96
00007fb5b801fb90 00007fb5dd9b9d60       96

Statistics:   
                  MT    Count    TotalSize Class Name
00007fb5dd9b9d60        3          288 System.Net.Sockets.Socket


''' and None

def tload_objs(debugger, command, result, args):
    opts = filter(None, command.split(' '))
    if len(opts) > 2:
        result.SetError("Extra arguments: %s" % command)
        return

    mt = opts[0]
    mtobj = load_mt_helper(debugger, mt)
    depth = 4 if len(opts) == 1 else int(opts[1])
    if not mtobj:
        result.SetError("Bad MT: %s" % mt)
        return

    cmd = 'dumpheap -mt %s' % mt
    if cmd in cmdhist:
        result.AppendMessage('MT %s objects already loaded' % mt)
        return
    cmdhist.add(cmd)

    cls = mtobj['__ClassName']
    hs = get_cmd_output(debugger, cmd)
    lines = filter(None, hs.split('\n'))
    if lines[0] != '         Address               MT     Size':
        result.SetError('Unexpected output: %s' % lines[0])
        return

    cnt = 0
    for l in lines[1:]:
        if l == 'Statistics:':
            break
        ts = filter(None, l.split(' '))
        addr = ts[0]
        mt = ts[1]

        # obj = dict(__Type = 'OBJ', __ClassName = cls, __Address = ts[0], __MT = ts[1], __Size = int(ts[2]))
        obj = load_any_helper(debugger, mt, addr, 0)
        if not obj:
            dprint('Unexpected output from (%s): %s' % (cmd, l))
            continue
        result.AppendMessage('%d - %s (%d)' % (cnt, addr, len(obj)))
        cnt += 1

        # save in objmap since dumpheap -mt is expensive
        if is_valid_addr(addr) and obj:
            objmap[addr] = obj

    result.AppendMessage('')
    result.AppendMessage('Total %d objs of %s found' % (cnt, cls))

def tfind_class(debugger, command, result, args):
    if not len(typemap):
        res = lldb.SBCommandReturnObject()
        tinit(lldb.debugger, '', res, None)

    cls = command
    for v in typemap.values():
        if re.search(cls, v['__ClassName']):
            # dprint(v)
            count = 0 if '__Count' not in v else v['__Count']
            result.AppendMessage('MT %s - Objects %6s - Class %s' % (v['__Address'], count, v['__ClassName']))

def tfind_obj(debugger, command, result, args):
    obj = command
    for v in objmap.values():
        s = json.dumps(v)
        # dprint('%s - %s' % (obj, s))
        if re.search(obj, s):
            result.AppendMessage('%s %s - Class %s' % (v['__Type'], v['__Address'], v['__ClassName']))

def load_any_helper(debugger, mt, addr, depth):
    # dprint('... load_any_helper %s %s %d ...' % (mt, addr, depth))
    if not is_valid_addr(addr):
        return None
    obj = load_obj_helper(debugger, addr, depth)
    if not obj:
        obj = load_struct_helper(debugger, mt, addr, depth)
    #if not obj:
    #    obj = load_array_helper(debugger, addr, depth)

    # cache it in tmpobjmap
    if obj:
        tmpobjmap[addr] = obj
    return obj

def load_field_helper(debugger, line, depth):
    # dprint('parsing field %s' % line)
#0007fb5ddbe1a90  4000115        8 ....SafeSocketHandle  0 instance 00007fb5b801f700 _handle
#000000000000000  4000157       f8                       0   static 0000000000000000 <>9__279_0

    ts = [
        line[0:16].strip(),
        line[17:25].strip(),
        line[26:34].strip(),
        line[35:55].strip(),
        line[56:58].strip(),
        line[59:67].strip(),
        line[68:84].strip(),
        line[85:].strip(),
    ]
    mt = ts[0]
    attr = ts[5]
    if 'TLstatic' == attr:
        name = line[68:].strip()
        val = None # will be loaded by load_obj_helper by checking TLstatic
    elif 'static' == attr and line[59:83].strip() == 'static dynamic statics':
        val, name = filter(None, line[68:].split('  '))
        name.strip()
        val.strip()
    else:
        name = ts[7]
        val = ts[6]

    obj = None
    if depth > 0 and 16 == len(val) and val.startswith('00007f'): # likely an address
        obj = load_any_helper(debugger, mt, val, depth - 1)

    mtobj = load_mt_helper(debugger, mt)
    cls = mtobj['__ClassName'] if mtobj else ts[3]

    field = dict(
        __Type = 'FIELD',
        __MT = mt,
        __Field = ts[1],
        __Offset = ts[2],
        __ClassName = cls,
        __VT = ts[4],
        __Attr = attr,
        __Value = val,
        __Name = name
    )

    return field

'''
(lldb) dumpobj 00007fb5b801f748
Name:        System.Net.Sockets.Socket
MethodTable: 00007fb5dd9b9d60
EEClass:     00007fb5ddb43160
Size:        96(0x60) bytes
File:        /usr/share/dotnet/shared/Microsoft.NETCore.App/3.1.3/System.Net.Sockets.dll
Fields:
              MT    Field   Offset                 Type VT     Attr            Value Name
00007fb5ddbe1a90  4000115        8 ....SafeSocketHandle  0 instance 00007fb5b801f700 _handle
00007fb5dd6960c8  4000123       52       System.Boolean  1 instance                0 _receivingPacketInformation
00007fb5ddb9f358  400012e       88 ...Private.CoreLib]]  0   static 00007fb5b801bda0 s_zeroTask
00007fb5dd6960c8  4000127       d8       System.Boolean  1   static                1 s_initialized
00007fb5dd8bb368  400084c       28 ...eading.Tasks.Task  0 TLstatic  t_currentTask
    >> Thread:Value 7ed5:0000000000000000 7f44:00007fb5b801ccb8 83b:0000000000000000 b59:0000000000000000 c35:0000000000000000 c36:0000000000000000 ec8:0000000000000000 ec7:0000000000000000
00007f38362560c8  400002c       10       System.Boolean  1   static dynamic statics NYI                 s_isValueWriteAtomic
''' and None

def load_obj_helper(debugger, addr, depth):    
    if not is_valid_addr(addr):
        dprint('Not valid addr %s' % addr)
        return None

    hs = get_cmd_output(debugger, 'dumpobj %s' % addr)
    lines = filter(None, hs.split('\n'))
    if not lines[0].startswith('Name:'):
        dprint('Unexpected output %s' % lines[0])
        return None
    if not lines[5].startswith('Fields:') and not 'Object' == lines[5] and not lines[5].startswith('String:'):
        dprint('Unexpected output %s' % lines[5])
        return None
    if 'None' == lines[6] and lines[4].startswith('Array:'):
        dprint('Unexpected output %s' % lines[4])
        dprint('Unexpected output %s' % lines[6])
        return load_array_helper(debugger, addr, depth)

    mt = filter(None, lines[1].split(' '))[1]
    mtobj = load_mt_helper(debugger, mt)
    cls = mtobj['__ClassName'] if mtobj else filter(None, lines[0].split(' '))[1]

    eecls = filter(None, lines[2].split(' '))[1]
    size = filter(None, lines[3].split(' '))[1]
    afile = filter(None, lines[4].split(' '))[1]

    obj = dict(__Type = 'OBJ', __ClassName = cls, __Address = addr, __MT = mt, __EEClass = eecls, __Size = size, __File = afile)
    dprint('... loading %s of class %s ...' % (addr, cls))
    
    if lines[5].startswith('String:'):
        obj['String'] = lines[5].split(':')[1].strip()

    field_index = 5
    for l in lines[field_index:]:
        if 'Fields:' == l:
            break
        field_index += 1
    
    if 'Fields:' != lines[field_index]:
        dprint('Unable to find a line starting with Fields:')
        return None

    if 'None' == lines[field_index + 1]:
        return obj

    for lindex in range(field_index + 2, len(lines)):
        l = lines[lindex]
        field = load_field_helper(debugger, l, depth)
        obj[field['__Name']] = field
        if 'TLstatic' == field['__Attr']:
            # next line will be thread value
            lindex += 1
            l = lines[lindex]
            if not l.startswith('    >> Thread:Value'):
                dprint('TLstatic variable value isnot provided in the next line\n%s' % l)
                return None
            field['__Value'] = l[20:-3]

    tmpobjmap[addr] = obj
    return obj

def load_struct_helper(debugger, mt, addr, depth):
    if not mt or not is_valid_addr(mt) or not is_valid_addr(addr):
        return None
    hs = get_cmd_output(debugger, 'dumpvc %s %s' % (mt, addr))
    lines = filter(None, hs.split('\n'))
    if not lines[0].startswith('Name:'):
        # dprint('Unexpected output %s' % line[0])
        return None
    if not lines[5].startswith('Fields:'):
        # dprint('Unexpected output %s' % line[5])
        return None
    if len(lines) <= 6:
        return None

    mt = filter(None, lines[1].split(' '))[1]
    mtobj = load_mt_helper(debugger, mt)
    cls = mtobj['__ClassName'] if mtobj else filter(None, lines[0].split(' '))[1]

    eecls = filter(None, lines[2].split(' '))[1]
    size = filter(None, lines[3].split(' '))[1]
    afile = filter(None, lines[4].split(' '))[1]
    obj = dict(__Type = 'OBJ', __ClassName = cls, __Address = addr, __MT = mt, __EEClass = eecls, __Size = size, __File = afile)
    # dprint('... loading %s of struct %s ...' % (addr, cls))
    
    for l in lines[7:]:
        field = load_field_helper(debugger, l, depth)
        obj[field['__Name']] = field

    objmap[addr] = obj
    return obj

'''

/// SOS command output format

(lldb) dumparray 00007fb5b801c9f0
Name:        System.Int32[]
MethodTable: 00007fb5dd6cd470
EEClass:     00007fb5dd6cd400
Size:        56(0x38) bytes
Array:       Rank 1, Number of elements 8, Type Int32
Element Methodtable: 00007fb5dd69a0e8
[0] 00007fb5b801ca00
[1] 00007fb5b801ca04
[2] 00007fb5b801ca08
[3] 00007fb5b801ca0c
[4] 00007fb5b801ca10
[5] 00007fb5b801ca14
[6] 00007fb5b801ca18
[7] 00007fb5b801ca1c

''' and None

def load_array_helper(debugger, addr, depth):
    hs = get_cmd_output(debugger, 'dumparray %s' % addr)
    lines = filter(None, hs.split('\n'))
    if not lines[0].startswith('Name:'):
        # dprint('Unexpected output %s' % lines[0])
        return None
    if not lines[5].startswith('Element Methodtable:'):
        # dprint('Unexpected output %s' % lines[5])
        return None
    
    mt = filter(None, lines[1].split(':'))[1].strip()
    elem_mt = filter(None, lines[5].split(':'))[1].strip()

    mtobj = load_mt_helper(debugger, mt)
    if not mtobj:
        dprint('Not found array MT %s' % mt)
        return None

    elem_mtobj = load_mt_helper(debugger, elem_mt)
    if not elem_mtobj:
        dprint('Not found element MT %s' % elem_mt)
        return None

    cls = mtobj['__ClassName']
    if cls in typeblacklist:
        dprint('Not loading blacklisted type: %s' % cls)
        return None

    elem_cls = elem_mtobj['__ClassName']
    info = filter(None, lines[4].split(','))[1].strip()
    # dprint('... loading %s of array %s - %s ...' % (addr, cls, info))
    
    arr = dict(__Type = 'ARRAY', __ClassName = cls, __Address = addr, __MT = mt, __ElementMT = elem_mt, __ElementClassName = elem_cls)
    for l in lines[6:]:
        ts = l.split(' ')
        index = int(ts[0][1:-1]) # removing `[` and `]` from `[num]`
        elem_addr = ts[1]
        item = load_any_helper(debugger, elem_mt, elem_addr, depth - 1) if elem_addr != 'null' else None
        val = dict(__Type = 'ARRAY_ITEM', __MT = elem_mt, __Index = index, __Value = elem_addr)
        arr[index] = val

    objmap[addr] = arr
    return arr

def tload_obj(debugger, command, result, args):
    if not len(objmap):
        result.SetError("Please run tinit first")
        return

    opts = filter(None, command.split(' '))
    if len(opts) > 2:
        result.SetError("Extra arguments: %s" % command)
        return

    addr = opts[0]
    depth = 0 if len(opts) == 1 else int(opts[1])
    obj = load_obj_helper(debugger, addr, depth)
    if not obj:
        result.SetError("Unable to load obj %s" % addr)
    result.AppendMessage("Object %s loaded" % addr)

'''
append to msg, at pos, with indent considered
'''
def msg_tab_helper2(msg, append, indent, pos):
    if len(msg) == 0:
        return append
    size_min = len(indent) + pos
    size_min = max(len(msg) + 1, size_min)
    msg += ' ' * (size_min - len(msg))
    return msg + append

'''
append to msg, at pos, with indent considered, newline if str is large
'''
def msg_tab_helper(msg, append, indent, pos):
    size_min = len(indent) + pos
    if len(msg) + 1 > size_min:
        msg += '\n' + ' ' * size_min
    else:
        msg += ' ' * (size_min - len(msg))
    return msg + append

#- [static]     NormalOutput = 00007fb5b801d2b0         (System.String)

def is_valid_addr(addr):
    return len(addr) == 16 and addr != null_addr and '00007' == addr[:5]

def dump_obj_helper(debugger, result, mt, addr, cur_depth, max_depth, visited):
    if not is_valid_addr(addr):
        return None
    if addr in objmap:
        obj = objmap[addr]
    elif addr in tmpobjmap:
        obj = tmpobjmap[addr]
    else:
        obj = load_any_helper(debugger, mt, addr, 0)
    
    if not obj:
        return None

    visited.add(addr)

    indent = '    ' * cur_depth
    result.AppendMessage('%s<< %s - %s >>' % (indent, obj['__Address'], obj['__ClassName']))

    is_array = obj['__Type'] == 'ARRAY'
    if is_array:
        elem_cls = obj['__ElementClassName']

    for (k, v) in obj.items():
        if isinstance(k, str) and k.startswith('__'):
            continue

        if is_array:
            if isinstance(v, str):
                dprint('obj = %s' % obj)
                dprint('k = %s' % k)
                dprint('v = %s' % v)
            index = v['__Index']
            val = v['__Value']
            if 'null' == val:
                continue

            # populate element            
            elem = '%s - [%d] %s' % (indent, index, val)
            if val in objmap and elem_cls != objmap[val]['__ClassName']:
                typ = '%s <== %s' % (elem_cls, objmap[val]['__ClassName'])
                elem = msg_tab_helper(elem, typ, indent, 40)
            result.AppendMessage(elem)

            if val not in visited and cur_depth < max_depth:
                dump_obj_helper(debugger, result, None, val, cur_depth + 1, max_depth, visited)
        else:
            val = v['__Value'] if not isinstance(v, str) else v
            attr = v['__Attr'] if not isinstance(v, str) else k
            mt = v['__MT'] if not isinstance(v, str) else None
            header = '%s - [%s]' % (indent, attr)
            kv = '%s = %s' % (k, val)
            
            # populate field
            field = msg_tab_helper(header, kv, indent, 16)
            if '__ClassName' in v:
                typ = v['__ClassName']
                if val in objmap and typ == 'System.String':
                    typ += ' - ' + objmap[val]['String']
                elif val in objmap and typ != objmap[val]['__ClassName']:
                    typ += ' <== ' + objmap[val]['__ClassName']
                field = msg_tab_helper(field, typ, indent, 56)
            result.AppendMessage(field)

            if val not in visited and cur_depth < max_depth:
                dump_obj_helper(debugger, result, mt, val, cur_depth + 1, max_depth, visited)

    if '__ThreadValueRaw' in obj:
        result.AppendMessage('%s Thread:Value => %s' % (indent, obj['__ThreadValueRaw']))

def tdump_obj(debugger, command, result, args):
    opts = filter(None, command.split(' '))
    if len(opts) > 3:
        result.SetError("Extra arguments: %s" % command)
        return

    mt = None if len(opts) < 3 else opts[0]
    addr = opts[0] if mt == None else opts[1]
    max_depth = 0 if len(opts) == 1 else int(opts[-1])
    dump_obj_helper(debugger, result, mt, addr, 0, max_depth, set())

def tdump_map(debugger, command, result, args):
    if '-f' in command:
        command, f = command.split('-f')
        filters = filter(None, f.split(' '))
    else:
        filters = []

    opts = filter(None, command.split(' '))
    if not opts:
        result.SetError("Object addres expected")
        return

    addr = opts[0]
    if not addr:
        result.SetError("Object addres expected")
        return

    obj = load_obj_helper(debugger, addr, 0)
    if not obj:
        result.SetError("Unable to find obj %s" % addr)
        return
    if '__Type' not in obj or obj['__Type'] != 'OBJ':
        result.SetError("Wrong obj type %s" % addr)
        return
    cls = obj['__ClassName']

    map_configs = {
        r'System.Collections.Concurrent.ConcurrentDictionary`2\[\[.*\],\[.*\]\]': dict(
            node_path = '_tables._buckets',
            rel_next_path = '_next',
            rel_key_path = '_key',
            rel_value_path = '_value'
        ),
        r'System.Collections.Generic.Dictionary`2\[\[.*\],\[.*\]\]': dict(
            node_path = '_entries',
            rel_next_path = None,       # Dictionary uses a flattened list that re-use the same array, so no need to track list
            rel_key_path = 'key',
            rel_value_path = 'value'
        ),
    }

    map_config = None
    for namepattern in map_configs:
        if re.match(namepattern, cls):
            map_config = map_configs[namepattern]
            break

    if not map_config:
        result.SetError("Object %s's type is not supported: %s" % (addr, cls))
        return
    result.AppendMessage('<< %s - %s >>' % (addr, cls))

    # step 1 - find all map nodes
    nodes = resolve_field_many(obj, map_config['node_path'])

    # step 2 - expand each node's linked list
    nodes = expand_list_by_field(nodes, map_config['rel_next_path'])

    # step 3 - produce key value pair
    objs = resolve_field_tuple(nodes, key = map_config['rel_key_path'], value = map_config['rel_value_path'] )

    # step 4 - dump as table
    mappings = [ 'key', 'value' ] + opts[1:]
    tbl = objs2table(objs, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)

def tdump_list(debugger, command, result, args):
    if '-f' in command:
        command, f = command.split('-f')
        filters = filter(None, f.split(' '))
    else:
        filters = []

    opts = filter(None, command.split(' '))
    if not opts:
        result.SetError("Object addres expected")
        return

    addr = opts[0]
    if not addr:
        result.SetError("Object addres expected")
        return

    obj = load_obj_helper(debugger, addr, 0)
    if not obj:
        result.SetError("Unable to find obj %s" % addr)
        return
    if '__Type' not in obj or obj['__Type'] != 'OBJ':
        result.SetError("Wrong obj type %s" % addr)
        return
    cls = obj['__ClassName']

    list_configs = {
        r'System.Collections.Generic.HashSet`1\[\[.*\]\]': dict(
            node_path = '_slots.value',
            count_path = '_count',
            rel_next_path = None,  # it uses flattened array, no need to track list
            rel_value_path = ''    # node is the value
        ),
        r'System.Collections.Generic.List`1\[\[.*\]\]': dict(
            node_path = '_items',
            count_path = '_size',
            rel_next_path = None,  # it uses flattened array, no need to track list
            rel_value_path = ''    # node is the value
        ),
        r'System.Collections.Concurrent.ConcurrentQueue`1\[\[.*\]\]': dict(
            node_path = '_head',
            count_path = None,    # this data struture doesn't have a Count mantained
            rel_next_path = '_nextSegment',
            rel_value_path = '_slots.Item'
        ),
    }

    list_config = None
    for namepattern in list_configs:
        if re.match(namepattern, cls):
            list_config = list_configs[namepattern]
            break

    if not list_configs:
        result.SetError("Object %s's type is not supported: %s" % (addr, cls))
        return
    result.AppendMessage('<< %s - %s >>' % (addr, cls))

    # step 1 - resolve count
    if list_config['count_path']:
        count = resolve_field_nest(obj, list_config['count_path'])
    else:
        count = 'Unknown'

    # step 2 - find list head node(s) (but ConcurrentQueue will start with 1 head node)
    nodes = resolve_field_many(obj, list_config['node_path'])

    # step 3 - trace linked list (due to ConcurrentQueue, this is done before resolve many)
    if list_config['rel_next_path']:
        nodes = expand_list_by_field(nodes, list_config['rel_next_path'])

    # step 4 - find all value nodes
    objs = resolve_field_many(nodes, list_config['rel_value_path'])

    # step 5 - dump as table
    mappings = [ 'value:' ] + opts[1:]
    tbl = objs2table(objs, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)
    result.AppendMessage('List Item Count: %s' % valfmt(count))

def tdump_link(debugger, command, result, args):
    if '-f' in command:
        command, f = command.split('-f')
        filters = filter(None, f.split(' '))
    else:
        filters = []

    opts = filter(None, command.split(' '))
    if not opts or len(opts) < 3:
        result.SetError("obj_addr head_path and next_path expected")
        return

    addr = opts[0]
    head_path = opts[1]
    next_path = opts[2]

    obj = load_obj_helper(debugger, addr, 0)
    if not obj:
        result.SetError("Unable to find obj %s" % addr)
        return
    if '__Type' not in obj or obj['__Type'] != 'OBJ':
        result.SetError("Wrong obj type %s" % addr)
        return
    cls = obj['__ClassName']
    result.AppendMessage('<< %s - %s >>' % (addr, cls))

    # step 1 - find list head node(s)
    nodes = resolve_field_many(obj, head_path)

    # step 2 - trace linked list
    nodes = expand_list_by_field(nodes, next_path)

    # step 3 - dump as table
    mappings = [ 'node:' ] + opts[3:]
    tbl = objs2table(nodes, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)

def resolve_obj(mt, addr):
    if addr in objmap:
        return objmap[addr]
    if addr in tmpobjmap:
        return tmpobjmap[addr]
    else:
        obj = load_any_helper(lldb.debugger, mt, addr, 0)

    if not obj:
        return addr
    return obj

def resolve_field(obj, fname):
    # dprint('resolve_field %s %s' %(obj, fname))
    if not obj or isinstance(obj, str):
        return None
    if fname not in obj:
        return 'NoField-' + fname
    field = obj[fname]
    if not isinstance(field, dict):
        return field
    
    mt = field['__MT']
    if '__Value' in field:
        val = field['__Value']
    elif '__Address' in field:
        val = field['__Address']
    else:
        val = ''
    obj = resolve_obj(mt, val)
    return obj

def resolve_field_nest(obj, fname_nest):
    # field_nest is separated by dot '.'
    # e.g. _rightEndPoint._address._addressOrScopeId
    fnames = filter(None, fname_nest.split('.'))

    # now 'recursively' apply the fname to obj
    for fname in fnames:
        obj = resolve_field(obj, fname)
    return obj

def resolve_field_many(obj, fname_nest):
    # field is separated by dot '.'
    # e.g. _rightEndPoint._address._addressOrScopeId
    #
    # one or more field segment can be an array 
    # and results will be expanded
    fnames = filter(None, fname_nest.split('.'))

    # start from an new array objs, if the input is not already array
    if isinstance(obj, list):
        objs = obj
    else:
        objs = [obj]

    # now 'recursively' apply the fname to all obj in objs
    for fname in fnames:
        # every level we may expand or shrink the array
        # first create a new array
        newobjs = []

        for obj in objs:
            obj = resolve_field(obj, fname)
            if obj == None:
                # skip adding if obj return None
                continue
            elif isinstance(obj, dict) and obj['__Type'] == 'ARRAY':
                # for array, instead of adding the array itself
                # add all child elements into newobjs
                for (k, field) in obj.items():
                    if not isinstance(k, int):
                        continue
                    # print field
                    obj = resolve_obj(field['__MT'], field['__Value'])
                    if obj == None or obj == 'null': # null is a special value returned from dumparray
                        continue
                    newobjs.append(obj)
            else:
                newobjs.append(obj)

        # set newobjs, and repeat to next level
        objs = newobjs
        # print objs
    return objs

def is_default_value(val):
    return val == null_addr or val == '' or val == '0' or val == None

def is_default_tuple(tup):
    for val in tup.values():
        if not is_default_value(val):
            return False
    return True

'''
takes an obj array, return a list of tuples, each tuple is a dict,
which the key is the name of the tuple, the value is the field path
applied to each of the obj.
'''
def resolve_field_tuple(objs, **tuple_paths):
    ret = []
    for obj in objs:
        tup = dict()
        for k, tpath in tuple_paths.items():
            tup[k] = resolve_field_nest(obj, tpath)
        if not is_default_tuple(tup):
            ret.append(tup)
    return ret

'''
takes a node array, each node is a head node of a linked list,
expend the node array by following the next node, until the list has
been exhausted, then return all nodes
'''
def expand_list_by_field(nodes, next_path):
    if not next_path:
        return nodes
    while True:
        start_size = len(nodes)
        for n in nodes:
            pnext = resolve_field_nest(n, next_path)
            if not pnext or pnext == null_addr or pnext in nodes:
                continue
            nodes.append(pnext)
        end_size = len(nodes)
        if end_size == start_size:
            break
    return nodes

def try_convert_enum(val, dic):
    try:
        return '%s:%s' % (dic[int(val)], val)
    except:
        return val

def pipe2func(p):
    if p.startswith('re/'):
        # regex
        dummy, pattern, replace = p.split('/')
        return lambda val: re.sub(pattern, replace, val)
    elif p.startswith('e/'):
        fn = 'enum' + p[2:]
        return lambda val: try_convert_enum(val, eval(fn))
    else:
        return eval(p)

def apply_pipes(val, pipes):
    if isinstance(val, dict):
        if val['__ClassName'] == 'System.String' and 'String' in val:
            val = val['String']
        else:
            val = val['__Address']
    for p in pipes:
        if val == None:
            break
        func = pipe2func(p) # it better be a valid function name
        val = func(val)
    return val

def obj2row(obj, mappings):
    row = dict()
    for m in mappings:
        # each mapping rule is in this format:
        # name:prop1.prop2.prop3|pipefunc1|pipefunc2
        # e.g. name:_rightEndPoint._address._addressOrScopeId|ip2str
        name, props_and_pipes = m.split(':') if ':' in m else (m, m)
        props_and_pipes = props_and_pipes.split('|')
        props = props_and_pipes[0]
        val = resolve_field_nest(obj, props)

        pipes = props_and_pipes[1:]
        val = apply_pipes(val, pipes)

        row[name] = valfmt(val)
    return row

def row_filter(row, filters):
    for f in filters:
        if '=~' in f:
            col, regex = f.split('=~')
            if not row[col] or not re.search(regex, row[col]):
                return False
        elif '!=' in f:
            col, notval = f.split('!=')
            if notval == row[col]:
                return False
        else:
            col, val = f.split('=')
            print ('%s %s %s' % (col, val, row[col]))
            if val != row[col]:
                return False
    return True

def type2table(cls, mappings, filters):
    objs = resolve_class_objs(cls)
    return objs2table(objs, mappings, filters)

def objs2table(objs, mappings, filters):
    tbl = []
    for obj in objs:
        row = obj2row(obj, mappings)
        # filter returns false if we don't want the row
        if not row_filter(row, filters):
            continue
        tbl.append(row)
    return tbl

def resolve_mt(cls):
    if is_valid_addr(cls):
        mtobj = load_mt_helper(lldb.debugger, cls)
        if mtobj:
            return cls, mtobj['__ClassName']
        else:
            return None, None
    if cls not in typemap:
        res = lldb.SBCommandReturnObject()
        tinit(lldb.debugger, '', res, None)
    return typemap[cls]['__Address'], cls

def is_regex(s):
    return '?' in s or '*' in s or '^' in s or '$' in s or '|' in s

def resolve_classname_regex(regex):
    return [k for k in typemap.keys() if re.search(regex, k)]

def resolve_class_objs(cls):
    if is_regex(cls):
        # handle regex that match to multiple classes
        objs = []
        for clsname in resolve_classname_regex(cls):
            # dprint('resolving cls %s' % clsname)
            objs += resolve_class_objs(clsname)
        # dprint('found %d objs' % len(objs))
        return objs

    # normal logic
    mt, cls = resolve_mt(cls)
    if not mt or not cls:
        return []
    res = lldb.SBCommandReturnObject()
    tload_objs(lldb.debugger, mt, res, None)
    return [ obj for obj in objmap.values() if obj['__ClassName'] == cls and obj['__Type'] != 'MT' ]

def tblfmt_json(debugger, table, mappings, result):
    for row in table:
        result.AppendMessage(json.dumps(row, sort_keys=True))

def tblfmt_kvp(debugger, table, mappings, result):
    for row in table:
        result.AppendMessage(json.dumps(row, sort_keys=True).replace('"', ''))

def valfmt(val):
    if val == None:
        return 'None' # use a different None so that it is easy to trace to this code
    else:
        return str(val)

def tblfmt_grid(debugger, table, mappings, result):
    if not table:
        return

    # honor original mappings order in grid mode
    cols = map(lambda m: m.split(':')[0], mappings)
    colsizes = map(
        lambda c: 1 + max(len(c), max(map(lambda r: len(r[c]), table))),
        cols
    )
    bar = '-' * sum(colsizes)

    header = ''
    pos = 0
    for i in range(len(cols)):
        header = msg_tab_helper2(header, cols[i], '', pos)
        pos += colsizes[i] # point to next pos

    result.AppendMessage(bar)
    result.AppendMessage(header)
    result.AppendMessage(bar)

    for r in table:
        line = ''
        pos = 0
        for i in range(len(cols)):
            val = r[cols[i]]
            line = msg_tab_helper2(line, val, '', pos)
            pos += colsizes[i] # point to next pos
        result.AppendMessage(line)
    result.AppendMessage(bar)
    result.AppendMessage(header)
    result.AppendMessage(bar)
    result.AppendMessage('Total %d Rows' % len(table))

# global variable
tblfmt = tblfmt_grid

def tset_tblfmt(debugger, command, result, args):
    global tblfmt
    tblfmt = eval('tblfmt_' + command) # this better resolve

def dump_table_helper(debugger, table, mappings, result):
    tblfmt(debugger, table, mappings, result)

def tdump_objs(debugger, command, result, args):
    opts = filter(None, command.split(' '))
    if len(opts) > 2:
        result.SetError("Extra arguments: %s" % command)
        return

    cls = opts[0]
    max_depth = 0 if len(opts) == 1 else int(opts[1])
    objs = resolve_class_objs(cls)
    cnt = 0
    for o in objs:
        result.AppendMessage('Object %d' % cnt)
        dump_obj_helper(debugger, result, o['__MT'], o['__Address'], 0, max_depth, set())
        cnt += 1

#
# Useful adhoc dump table commands:
#   # Dump all Thread objs
#   tdump_tbl 00007f3836264c00 this: id:_managedThreadId pri:_priority name:_name exec_ctx:_executionContext sync_ctx:_synchronizationContext
# 
def tdump_tbl(debugger, command, result, args):
    if '-f' in command:
        command, f = command.split('-f')
        filters = filter(None, f.split(' '))
    else:
        filters = []

    opts = filter(None, command.split(' '))
    if not opts:
        return

    cls = opts[0]
    if not cls:
        return

    mappings = opts[1:]
    dprint('%s, %s, %s' % (cls, mappings, filters))
    tbl = type2table(cls, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)

def ip2str(ip):
    # For struct.pack reference: https://docs.python.org/2/library/struct.html#struct.pack
    return socket.inet_ntoa(struct.pack('<L', int(ip)))

def af6str(bytearray_addr):
    if not is_valid_addr(bytearray_addr):
        return bytearray_addr

    byte_start = int(bytearray_addr, 16) + 16
    af6_size = 16
    eref = lldb.SBError()
    memory = process.ReadMemory(byte_start, af6_size, eref)
    if eref.Success():
        #print ('ip:%s' % socket.inet_ntoa(memory[4:8]))
        #return memory
        #print ('ip:%s' % socket.inet_ntoa(memory[4:8]))
        return socket.inet_ntoa(memory[4:8])
    else:
        dprint('af6str(%s) :%s' % (bytearray_addr, str(eref)))
        return bytearray_addr

def tdump_socks(debugger, command, result, args):
    cls = 'System.Net.Sockets.Socket'
    mappings = [
        'this:',
        'safehandle:_handle',
        'connected:_isConnected',
        'disconnected:_isDisconnected',
        'blocking:_willBlock',
        'listening:_isListening',
        'nbconnecting:_nonBlockingConnectInProgress',
        'right_port:_rightEndPoint._port',
        'right_ip:_rightEndPoint._address._addressOrScopeId|ip2str',
        'remote_port:_remoteEndPoint._port',
        'remote_ip:_remoteEndPoint._address._addressOrScopeId|ip2str',
        'nbconnect_port:_nonBlockingConnectRightEndPoint._port',
        'nbconnect_ip:_nonBlockingConnectRightEndPoint._address._addressOrScopeId|ip2str',
    ]
    filters = filter(None, command.split(' '))
    tbl = type2table(cls, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)

def tdump_sockaops(debugger, command, result, args):
    cls = 'SocketAsyncContext.*Operation$'
    mappings = [
        'this:',
        'class:__ClassName|re/.*\+(.*)/\\1',
        'engine:AssociatedContext._asyncEngineToken._engine',
        'op_handle:AssociatedContext._asyncEngineToken._handle',
        'state:_state|e/SockAsyncOpQueueState',
        'error:ErrorCode|e/SocketError',
        'addr:SocketAddress|af6str',
        'next:Next',
    ]
    filters = filter(None, command.split(' '))
    tbl = type2table(cls, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)

def tdump_eps(debugger, command, result, args):
    cls = 'System.Net.IPEndPoint'
    mappings = [
        'this:',
        'ip:_address._addressOrScopeId|ip2str',
        'port:_port',
    ]
    filters = filter(None, command.split(' '))
    tbl = type2table(cls, mappings, filters)
    dump_table_helper(debugger, tbl, mappings, result)

def tgrep(debugger, command, result, args):
    opts = filter(None, command.split(' '))
    regex = opts[0]
    enclosed_command = ' '.join(opts[1:])

    res = get_cmd_output_res(debugger, enclosed_command)
    if not res.Succeeded():
        result.SetError(res.GetError())
        result.AppendMessage(res.GetOutput())
        return

    lines = res.GetOutput().split('\n')
    for l in lines:
        if not re.search(regex, l):
            continue
        result.AppendMessage(l)

def tee(debugger, command, result, args):
    opts = filter(None, command.split(' '))
    filename = opts[0]
    enclosed_command = ' '.join(opts[1:])
    res = get_cmd_output_res(debugger, enclosed_command)
    if not res.Succeeded():
        result.SetError(res.GetError())
        result.AppendMessage(res.GetOutput())
        return

    f=open(filename, "w")
    hs = res.GetOutput()
    f.write(hs)
    result.AppendMessage(hs)

def tall(debugger, command, result, args):
    ci = debugger.GetCommandInterpreter()
    if '-f' in command:
        command, regex = command.split('-f')
    else:
        regex = None

    cmds = command.split(';')
    tmpf = open(tmp_file, "w")
    outf = debugger.GetOutputFileHandle()
    errf = debugger.GetErrorFileHandle()
    debugger.SetOutputFileHandle(tmpf, True)
    debugger.SetErrorFileHandle(tmpf, True)

    for t in process:
        found_in_thread = False
        tsel = 'thread select %d' % t.GetIndexID()
        get_cmd_output(debugger, tsel)

        for c in cmds:
            out = get_cmd_output(debugger, c)
            for l in out.split('\n'):
                if regex == None or re.search(regex, l):
                    result.AppendMessage(l)
                    found_in_thread = True

        if regex == None or found_in_thread:
            result.AppendMessage('^^^ output from %s ^^^\n' % tsel)

    debugger.SetOutputFileHandle(outf, True)
    debugger.SetErrorFileHandle(errf, True)
    tmpf.close()

def thelp(debugger, command, result, args):
    result.AppendMessage('thelp - this command')
    result.AppendMessage(' ')
    result.AppendMessage('tinit - initialize by running dumpheap -stat')
    result.AppendMessage('tsave - save loaded objmap and typemap to a file')
    result.AppendMessage('tload - load saved objmap and typemap from a file')
    result.AppendMessage(' ')
    result.AppendMessage('tset_tblfmt kvp|json|grid[default] - set output format for tdump_tbl')
    result.AppendMessage('tset_debug [1|0] - set debug output')
    result.AppendMessage(' ')
    result.AppendMessage('tgrep <regex> command - filter output of a command')
    result.AppendMessage('tee <file.txt> command - save a copy of command output to file')
    result.AppendMessage('tall command1; command2 - for each thread, run semicolon separated commands')
    result.AppendMessage(' ')
    result.AppendMessage('tload_objs <MT> - load all objects of a type')
    result.AppendMessage('tfind_class <name_regex> - find class')
    result.AppendMessage('tfind_obj <value_regex> - find object')
    result.AppendMessage(' ')
    result.AppendMessage('tdump_obj <addr> [depth - default 0] - dump object')
    result.AppendMessage('tdump_objs <MT> [depth - default 0] - dump object')
    result.AppendMessage('tdump_tbl <MT>|<regex> <column_mappings>... [-f filters] - dump table with mapping rules')
    result.AppendMessage('tdump_map <addr> [column_mappings] [-f filters] - dump a map (Dictioanry, or ConcurrentDicionary)')
    result.AppendMessage('tdump_list <addr> [olumn_mappings] [-f filters] -- dump a list (List, HashSet, or ConcurrentQueue)')
    result.AppendMessage('tdump_link <addr> <node_path> <next_path> [column_mappings] - dump a linked list')
    result.AppendMessage(' ')
    result.AppendMessage('tdump_socks - dump sockets')
    result.AppendMessage('tdump_sockaops - dump socket async operations')
    result.AppendMessage('tdump_eps - dump endpoint objects')
    result.AppendMessage(' ')
    result.AppendMessage('Aliases:')
    result.AppendMessage('tsh <shell command> = platform shell - run command on shell')
    result.AppendMessage('tdo = tdump_obj')
    result.AppendMessage('tdos = tdump_objs')
    result.AppendMessage('tdm = tdump_map')
    result.AppendMessage('tdl = tdump_list')
    result.AppendMessage('tdk = tdump_link')
    result.AppendMessage('tdt = tdump_tbl')

def __lldb_init_module(debugger, args):
    global process, process_name
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    process_name = process.GetProcessInfo().GetName()

    m = __name__
    print("%s extention loaded! Type thelp for command help" % m)

    v = __name__[len(default_name):]
    if v:
        debugger.HandleCommand('script %s.copystate(%s)' % (m, default_name))
        print("%s extension imported state from %s" % (m, default_name))

    # aliases
    debugger.HandleCommand('command alias tsh%s platform shell' % v)

    # extension commands
    debugger.HandleCommand('command script add -f %s.thelp thelp%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tinit tinit%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tsave tsave%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tload tload%s' % (m,v))

    debugger.HandleCommand('command script add -f %s.tset_tblfmt tset_tblfmt%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tset_debug tset_debug%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tgrep tgrep%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tee tee%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tall tall%s' % (m,v))

    debugger.HandleCommand('command script add -f %s.tload_obj tload_obj%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tload_objs tload_objs%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tfind_class tfind_class%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tfind_obj tfind_obj%s' % (m,v))

    debugger.HandleCommand('command script add -f %s.tdump_obj tdump_obj%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_obj tdo%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_objs tdump_objs%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_objs tdos%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_tbl tdump_tbl%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_tbl tdt%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_map tdump_map%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_map tdm%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_list tdump_list%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_list tdl%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_link tdump_link%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_link tdk%s' % (m,v))

    debugger.HandleCommand('command script add -f %s.tdump_socks tdump_socks%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_eps tdump_eps%s' % (m,v))
    debugger.HandleCommand('command script add -f %s.tdump_sockaops tdump_sockaops%s' % (m,v))
