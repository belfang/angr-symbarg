#!/usr/bin/env python

import angr, claripy, time, simuvex

def basic_symbolic_execution():
    start_time = time.time()

    p = angr.Project('./test', load_options={'auto_load_libs':True})

    files = {'./input1': angr.storage.file.SimFile("./input1", "r", size=300)}

    #state = p.factory.entry_state(args=['./test'], add_options=angr.options.unicorn)
    state = p.factory.entry_state(fs=files, remove_options={simuvex.o.LAZY_SOLVES}, args=['./test', '-l', './input1'])
    state.posix.fs['./input1'].seek(0)
    state.posix.fs['./input1'].length=300


    #print state.posix.files[0].size
    sm = p.factory.simgr(state)

    # Uncomment the following line to spawn an IPython shell when the program
    # gets to this point so you can poke around at the four objects we just
    # constructed. Use tab-autocomplete and IPython's nifty feature where if
    # you stick a question mark after the name of a function or method and hit
    # enter, you are shown the documentation string for it.
    # import IPython; IPython.embed()

    sm.step(until=lambda lpg: (time.time() - start_time) > 30)

    print len(sm.deadended)
    print len(sm.active)

    #state.posix.files[3].seek(0)
    #state.posix.files[3].length=300

    i = 0
    while (i < len(sm.deadended)):
	print i
    	#sm.deadended[i].state.posix.files[3].length=300
        #print sm.deadended[i].state.posix.fs['./input1'].length
        print sm.deadended[i].state.posix.dump_file_by_path('./input1')
        i = i+1

    output=open("deadended1", "w+")
    output.write(sm.deadended[0].posix.dump_file_by_path('./input1'))
    output2=open("deadended2", "w+")
    output2.write(sm.deadended[1].posix.dump_file_by_path('./input1'))
    output3=open("deadended3", "w+") 
    output3.write(sm.deadended[2].posix.dump_file_by_path('./input1'))


    # if 'SOSNEAKY' in input_0:
    #     return input_0
    # else:
    #     return input_1

def test():
    pass        # appease our CI infrastructure which expects this file to do something lmao

if __name__ == '__main__':
    print basic_symbolic_execution()

# You should be able to run this program and pipe its into fauxware in order to
# produce a "sucessfully authenticated" message
