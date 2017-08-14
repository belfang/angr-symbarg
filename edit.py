#!/usr/bin/env python

import angr, claripy, time, sys, os 


# Look at fauxware.c! This is the source code for a "faux firmware" (@zardus
# really likes the puns) that's meant to be a simple representation of a
# firmware that can authenticate users but also has a backdoor - the backdoor
# is that anybody who provides the string "SOSNEAKY" as their password will be
# automatically authenticated.


# Potential interface:  ptyhon_test.py /bin/echo 10 4


# workon ang 
# python edit.py /bin/echo 2 10 7

def basic_symbolic_execution():
    start_time = time.time()

    # We can use this as a basic demonstration of using angr for symbolic
    # execution. First, we load the binary into an angr project.

    print len(sys.argv)

    #create list of input from command line
    commandLine = list()
    i = 2
    while (i < len(sys.argv)):
	commandLine.append(int(sys.argv[i]))	
	i = i+1

    #project name, "echo" is in argv[1]
    p = angr.Project(sys.argv[1]) 


    # Now, we want to construct a representation of symbolic program state.
    # SimState objects are what angr manipulates when it symbolically executes
    # binary code.
    # The entry_state constructor generates a SimState that is a very generic
    # representation of the possible program states at the program's entry
    # point. There are more constructors, like blank_state, which constructs a
    # "blank slate" state that specifies as little concrete data as possible,
    # or full_init_state, which performs a slow and pedantic initialization of
    # program state as it would execute through the dynamic loader.

    #create dictionary of bitvectors as values
    d={}
    x = 2
    while (x < len(sys.argv)):
	d["arg{0}".format(x-2)]=claripy.BVS("arg{0}".format(x-2), commandLine[x-2]*8)
	x = x+1

    
    #create list of arguments used in creating state
    arguments = list()
    arguments.append(sys.argv[1])
    j = 2
    while (j < len(sys.argv)):
	arguments.append(d["arg{0}".format(j-2)])
	j = j+1
 
    state = p.factory.entry_state(args=arguments) #is this using the keys or the values?


    # Now, in order to manage the symbolic execution process from a very high
    # level, we have a SimulationManager. SimulationManager is just collections
    # of states with various tags attached with a number of convenient
    # interfaces for managing them.

    sm = p.factory.simgr(state)

    # Uncomment the following line to spawn an IPython shell when the program
    # gets to this point so you can poke around at the four objects we just
    # constructed. Use tab-autocomplete and IPython's nifty feature where if
    # you stick a question mark after the name of a function or method and hit
    # enter, you are shown the documentation string for it.

    # import IPython; IPython.embed()

    # Now, we begin execution. This will symbolically execute the program until
    # we reach a branch statement for which both branches are satisfiable.

    sm.step(until=lambda lpg: (time.time() - start_time) > 35)

    # If you look at the C code, you see that the first "if" statement that the
    # program can come across is comparing the result of the strcmp with the
    # backdoor password. So, we have halted execution with two states, each of
    # which has taken a different arm of that conditional branch. If you drop
    # an IPython shell here and examine sm.active[n].se.constraints
    # you will see the encoding of the condition that was added to the state to
    # constrain it to going down this path, instead of the other one. These are
    # the constraints that will eventually be passed to our constraint solver
    # (z3) to produce a set of concrete inputs satisfying them.

    # As a matter of fact, we'll do that now.

    print len(sm.deadended)
    print len(sm.active)
    

    os.makedirs("../fauxware/active_dir", 0755)
    os.chdir("active_dir")	    
    k = 1    
    count = 0
    for count in range(len(sys.argv)-2):
        for k in range(len(sm.active)):
	    output = open("active{}_{}.bin".format(k, count), "w+")
	    output.write(sm.active[k].solver.any_str(d.get("arg{0}".format(count))))
	    #print sm.active[k].solver.any_str(d.get("arg{0}".format(count)))	
	    k = k+1
	count = count+1
    os.chdir("../")
    
    
    os.makedirs("../fauxware/deadended_dir", 0755)
    os.chdir("deadended_dir")	    
    k = 1    
    count = 0
    for count in range(len(sys.argv)-2):
	for k in range(len(sm.deadended)):
	    output = open("deadended{}_{}.bin".format(k, count), "w+")
	    output.write(sm.deadended[k].solver.any_str(d.get("arg{0}".format(count))))
	    #print sm.deadended[k].solver.any_str(d.get("arg{0}".format(count)))	
	    k = k+1
	count = count+1  
    os.chdir("../")  


    # We have used a utility function on the state's posix plugin to perform a
    # quick and dirty concretization of the content in file descriptor zero,
    # stdin. One of these strings should contain the substring "SOSNEAKY"!

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
