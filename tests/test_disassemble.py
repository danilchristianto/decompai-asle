import os
import pytest
import src.utils as utils

def test_disassemble_function():
    # Path to the binary provided for testing
    binary_path = os.path.join("binaries", "ch2.bin")
    function_name = "check_one_fd"
    
    # Ensure the binary exists before testing
    assert os.path.exists(binary_path), f"Binary file not found: {binary_path}"
    
    # Attempt to extract the assembly for the function
    asm = utils.disassemble_function(binary_path, function_name)
    
    # Verify that the returned assembly is not an error message
    assert "Function check_one_fd not found." not in asm, "The function was not found in the binary."
    assert asm.strip() != "", "The disassembled output is empty."
    
    # Optionally, check that the output contains expected markers (e.g., the function name)
    assert function_name in asm, f"Expected function name '{function_name}' not found in the output."
    
    function_label = "080485f0 <check_one_fd>:"
    first_line = "80485f0:	55                   	push   %ebp"
    last_line = "80486b9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi"
    
    # Verify that the assembly contains expected instructions
    assert function_label in asm, f"Expected instruction '{function_label}' not found in the output."
    assert first_line in asm, f"Expected instruction '{first_line}' not found in the output."
    assert last_line in asm, f"Expected instruction '{last_line}' not found in the output."

def test_disassemble_binary():
    # Path to the binary provided for testing
    binary_path = os.path.join("binaries", "ch1.bin")
    
    # Ensure the binary exists before testing
    assert os.path.exists(binary_path), f"Binary file not found: {binary_path}"
    
    # Attempt to disassemble the binary
    asm = utils.disassemble_binary(binary_path)
    normalized_asm = " ".join(asm.split())
    
    # Verify that the returned assembly is not an error message
    assert "ch1.bin:     file format elf32-i386" in asm, "The binary was not disassembled."
    
    # Optionally, check that the output contains expected markers (e.g., the binary name)
    expected = "80487f3:       e8 00 00 00 00          call   80487f8 <_fini+0xc>"
    normalized_expected = " ".join(expected.split())
    assert normalized_expected in normalized_asm, "Expected call instruction not found."

if __name__ == "__main__":
    pytest.main()