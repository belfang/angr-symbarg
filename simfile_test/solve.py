#!/usr/bin/env python

import angr

simfile_size = 50

def get_simfile_content(s, file_path):
    fd = s.posix.filename_to_fd(file_path)
    if(fd == None):
        print "No fd found, use dump_file_by_path(): " + file_path
        return s.posix.dump_file_by_path(file_path)
    else:
        print "fd found \'" + str(fd) + "\': " + file_path
        return s.posix.dumps(fd)

def print_simfile_content(s):
    print "====================="
    print "print_simfile_content"
    print "====================="

    concrete_value = get_simfile_content(s, './input_file')
    print  "./input_file: " + concrete_value + " (" + str(len(concrete_value)) + " bytes)"

def basic_symbolic_execution():
    p = angr.Project('./test', load_options={'auto_load_libs':True})

    arguments = ('./test','./input_file')
    files = {'./input_file': angr.storage.file.SimFile('./input_file', 'r', size = simfile_size)}
    state = p.factory.entry_state(args=arguments, fs=files)

    sm = p.factory.simgr(state)
    sm.step(until=lambda lpg: len(lpg.active) > 1)

    if(len(sm.active) >= 2):
        print_simfile_content(sm.active[0])
        print_simfile_content(sm.active[1])
    else:
        print "Active states: " + str(len(sm.active))

if __name__ == '__main__':
    basic_symbolic_execution()
