#!/usr/bin/env python

import angr, claripy, time, sys, os, simuvex
import ntpath
from xml.dom import minidom

TIMEOUT = 7

def check_argv(argv):
    if not len(argv) == 2:
        print "[ERROR] Only exact one argument is valid!"
        sys.exit()

    xml_path = argv[1]

    if not os.path.isfile(xml_path):
        print "[ERROR] input file \'" + xml_path + "\' does not exist!"
        sys.exit()

    return xml_path

def parse_xml_exe(parsed_xml):
    target_exe = parsed_xml.getElementsByTagName('exec')[0].childNodes[0].nodeValue

    if not os.path.isfile(target_exe):
        print "[ERROR] target executable \'" + target_exe + "\' does not exist!"
        sys.exit()
    print "Target executable \'" + target_exe + "\' ..."

    return target_exe

def parse_xml_argv(parsed_xml, dic_args):
    xml_args = parsed_xml.getElementsByTagName('arg')

    for s in xml_args:
        index = int(s.attributes['index'].value)
        value = str(s.attributes['value'].value)
        size = 0
        if s.attributes['size'].value:
            size = int(s.attributes['size'].value)
        if size < len(value):
            size = len(value)
        concolic = s.attributes['concolic'].value

	if concolic == "true":
	    dic_args["arg_{0}".format(index)] = claripy.BVS("arg_{0}".format(index), size*8)
	else:
	    dic_args["arg_{0}".format(index)] = value

    for k,v in dic_args.iteritems():
        if isinstance(v, str):
            print k + ": string instance, concrete argument, value = " + v
        elif isinstance(v, claripy.ast.Bits):
            print k + ": claripy AST instance, symbolic argument"
        else:
            print "[Error] " + k + ": wrong type"
            print type(v)
            sys.exit()

    return dic_args

def parse_xml_file(parsed_xml):
    xml_files = parsed_xml.getElementsByTagName('file')
    list_files = list()

    for f in xml_files:
        path = str(f.attributes['path'].value)
        size = int(f.attributes['size'].value)
        concolic = f.attributes['concolic'].value

	if concolic == "true":
            # filename = ntpath.basename(path)
            list_files.append([path, size])
        else:
            print "[Error] Non-concolic file is given: " + path
            sys.exit()

    ## XXX: sequence of files are not the same as it is in xml file
    for k in list_files:
        print "concolic file: " + k[0] + ", " + str(k[1])

    return list_files

def parse_xml_stdin(parsed_xml):
    xml_stdin = parsed_xml.getElementsByTagName('stdin')
    if not xml_stdin:
        return 0
    if not len(xml_stdin) == 1:
        print "[Error] more than one stdin is given, please check input xml file"
        sys.exit()

    size = int(xml_stdin[0].attributes['size'].value)
    concolic = xml_stdin[0].attributes['concolic'].value

    if not concolic == "true":
        print "[Error] Non-concolic stdin is given"
        sys.exit()

    print "stdin_size from xml: " + str(size)
    return size

def exec_angr(target_exe, dic_args, list_files, stdin_size):
    print "========="
    print "exec_angr"
    print "========="

    p = angr.Project(target_exe, load_options={'auto_load_libs':True})

    ## prepare arguments
    arguments=list()
    for i in range(0, len(dic_args)):
        key = "arg_{0}".format(i)
        if not key in dic_args:
            print "[ERROR] incomplete argv list from xml: \'" + key + "\' not found"
            sys.exit()
        arguments.append(dic_args[key])

    ## prepare files
    files = {}
    for f in list_files:
        file_path = f[0]
        file_size = f[1]
        files[file_path] = angr.storage.file.SimFile(file_path, "r", size = file_size)
        arguments.append(file_path)

    ## prepare stdin
    if not stdin_size == 0:
        files['/dev/stdin'] = angr.storage.file.SimFile("/dev/stdin", "r", size = stdin_size)

    ## debug prints
    for v in arguments:
        if isinstance(v, str):
            print "concrete argument: " + v
        elif isinstance(v, claripy.ast.Bits):
            print "symbolic argument"
        else:
            print "[Error] " + v + ": wrong type"
            print type(v)
            sys.exit()
    for k,v in files.iteritems():
        print "symbolic file: " + k

    state = p.factory.entry_state(args=arguments, fs=files)
    sm = p.factory.simgr(state)

    start_time = time.time()
    # sm.step(until=lambda lpg: (time.time() - start_time) > TIMEOUT)
    sm.step(until=lambda lpg: len(lpg.active) > 1)

    return sm

def get_test_case(s, dic_args, list_files, stdin_size):
    print "--------------"
    print "get_test_case:"
    print "--------------"

    for k,v in dic_args.iteritems():
        if not isinstance(v, claripy.ast.Bits):
            continue
        concrete_value = s.solver.any_str(v)
        # concrete_value = s.solver.any_int(v)
        print k + ": " + str(concrete_value)

    for f in list_files:
        file_path = f[0]
        concrete_value = s.posix.dump_file_by_path(file_path)
        # fd = s.posix.filename_to_fd(file_path)
        # if(fd == None):
        #     concrete_value = ''
        # else:
        #     print "fd = " + str(fd)
        #     concrete_value = s.posix.dumps(fd)

        print file_path + ": " + concrete_value + ", " + str(len(concrete_value))

    if not stdin_size == 0:
        fd = s.posix.filename_to_fd("/dev/stdin")
        stdin_content = s.posix.dumps(fd)
        # stdin_content = s.posix.dump_file_by_path("/dev/stdin")
        print "stdin_content: " + stdin_content + ", " + str(len(stdin_content))

def collect_angr_result(sm, dic_args, list_files, stdin_size):
    print "==================="
    print "collect_angr_result"
    print "==================="

    print "deadended: " + str(len(sm.deadended))
    print "active: " + str(len(sm.active))

    for s in sm.deadended:
        get_test_case(s, dic_args, list_files, stdin_size)

    for s in sm.active:
        get_test_case(s, dic_args, list_files, stdin_size)

def angr_xml_ui(argv):
    input_xml = check_argv(argv)
    parsed_xml = minidom.parse(input_xml)

    dic_args  = {}

    ## 1. parse target executable
    target_exe = parse_xml_exe(parsed_xml)
    dic_args["arg_0"] = str(target_exe)

    ## 2. parse xml arguments
    dic_args = parse_xml_argv(parsed_xml, dic_args)

    ## 3. parse xml files
    list_files = parse_xml_file(parsed_xml)

    ## 4. parse xml stdin
    stdin_size = parse_xml_stdin(parsed_xml)

    ## 5. start angr with parsed args, files and stdin
    sm = exec_angr(target_exe, dic_args, list_files, stdin_size)

    ## 6. collect angr's result
    collect_angr_result(sm, dic_args, list_files, stdin_size)

    return

if __name__ == '__main__':
    angr_xml_ui(sys.argv)
