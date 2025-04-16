#!/usr/bin/env python2.7
import os
import sys
import json

def decompile_function():
    print("Decompiling function with Ghidra")

    # Ghidra passes arguments via getScriptArgs()
    args = getScriptArgs()
    if len(args) != 1:
        print("Usage: decompile_function.py <function_name>")
        exit(1)

    function_name = args[0]
    
    print("Function name: {}".format(function_name))
    
    # Get the current program
    program = currentProgram
    if not program:
        print("No program loaded")
        sys.exit(1)
        
    
        # Find the function
    function = getFunction(function_name)
    if not function:
        print("Function {} not found".format(function_name))
        functions = getGlobalFunctions(function_name)
        if not functions:
            print("Function {} not found".format(function_name))
            
            # Print all functions available in the program
            # print("Functions available in the program:")
            # for func in getGlobalFunctions():
            #     print(func.getName())
            sys.exit(1)
        function = functions[0]
    
    # Get the decompiler
    decompiler = ghidra.app.decompiler.DecompInterface()
    decompiler.openProgram(program)
    
    # Decompile the function
    decompile_results = decompiler.decompileFunction(function, 30, monitor)
    if not decompile_results.decompileCompleted():
        print("Decompilation failed")
        sys.exit(1)
    
    # Get the decompiled code
    decompiled_code = decompile_results.getDecompiledFunction().getC()
    print("/* Decompiled '{}' */".format(function_name))
    print(decompiled_code)
    
    # Output the result as JSON
    result = {
        "function_name": function_name,
        "decompiled_code": decompiled_code
    }
    return json.dumps(result)

if __name__ == "__main__":
    decompile_function() 