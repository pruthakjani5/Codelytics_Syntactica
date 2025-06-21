import streamlit as st
import ast
import re
import tempfile
import os
import textwrap
from typing import Dict, List, Tuple, Any
import google.generativeai as genai
import graphviz
from collections import defaultdict
import javalang
import subprocess
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Streamlit page
st.set_page_config(
    page_title="Codelytics Syntactica: Code Complexity Analyzer",
    page_icon="🔍",
    layout="wide"
)

class CyclomaticComplexityAnalyzer:
    """Calculates cyclomatic complexity for different programming languages"""
    
    def __init__(self):
        self.complexity_keywords = {
            'python': ['if', 'elif', 'for', 'while', 'and', 'or', 'except', 'with', 'assert', 'lambda'],
            'java': ['if', 'else if', 'for', 'while', 'do', 'switch', 'case', '&&', '||', 'catch', '?'],
            'javascript': ['if', 'else if', 'for', 'while', 'do', 'switch', 'case', '&&', '||', 'catch', '?'],
            'cpp': ['if', 'else if', 'for', 'while', 'do', 'switch', 'case', '&&', '||', 'catch', '?'],
            'c': ['if', 'else if', 'for', 'while', 'do', 'switch', 'case', '&&', '||']
        }
    
    def analyze_python_ast(self, code: str) -> Tuple[int, Dict]:
        """Analyze Python code using AST"""
        try:
            tree = ast.parse(code)
            complexity = 1  # Base complexity
            details = defaultdict(int)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    complexity += 1
                    details[type(node).__name__] += 1
                elif isinstance(node, ast.BoolOp):
                    complexity += len(node.values) - 1
                    details['BoolOp'] += len(node.values) - 1
                elif isinstance(node, ast.ExceptHandler):
                    complexity += 1
                    details['ExceptHandler'] += 1
                elif isinstance(node, ast.Lambda):
                    complexity += 1
                    details['Lambda'] += 1
                    
            return complexity, dict(details)
        except:
            return self.analyze_text_based(code, 'python')
    
    def analyze_java_ast(self, code: str) -> Tuple[int, Dict]:
        """Analyze Java code using javalang"""
        try:
            tree = javalang.parse.parse(code)
            complexity = 1
            details = defaultdict(int)
            
            for path, node in tree:
                if isinstance(node, (javalang.tree.IfStatement, javalang.tree.ForStatement, 
                                   javalang.tree.WhileStatement, javalang.tree.DoStatement,
                                   javalang.tree.SwitchStatement)):
                    complexity += 1
                    details[type(node).__name__] += 1
                elif isinstance(node, javalang.tree.CatchClause):
                    complexity += 1
                    details['CatchClause'] += 1
                    
            return complexity, dict(details)
        except:
            return self.analyze_text_based(code, 'java')
    
    def analyze_text_based(self, code: str, language: str) -> Tuple[int, Dict]:
        """Fallback text-based analysis"""
        complexity = 1
        details = defaultdict(int)
        keywords = self.complexity_keywords.get(language, self.complexity_keywords['python'])
        
        # Remove comments and strings
        if language == 'python':
            code = re.sub(r'#.*|""".*?"""|\'\'\'.*?\'\'\'', '', code, flags=re.DOTALL)
        elif language in ['java', 'cpp', 'c', 'javascript']:
            code = re.sub(r'//.*|/\*.*?\*/', '', code, flags=re.DOTALL)
        
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            matches = len(re.findall(pattern, code, re.IGNORECASE))
            if matches > 0:
                complexity += matches
                details[keyword] += matches
                
        return complexity, dict(details)
    
    def calculate_complexity(self, code: str, language: str) -> Tuple[int, Dict]:
        """Main method to calculate complexity"""
        if language == 'python':
            return self.analyze_python_ast(code)
        elif language == 'java':
            return self.analyze_java_ast(code)
        else:
            return self.analyze_text_based(code, language)

class CodeQualityAnalyzer:
    """Analyzes code quality metrics beyond complexity"""
    
    def __init__(self):
        self.patterns = {
            'python': {
                'code_smells': {
                    'long_function': r'def\s+\w+\([^)]*\):(?:(?!def).)*?(?:\n\s*\w+){20,}',
                    'too_many_parameters': r'def\s+\w+\((?:[^,]+,){5,}[^)]+\):',
                    'magic_numbers': r'(?<!\w)[-+]?[0-9]+(?:\.[0-9]+)?(?!\w)(?!\s*[=*/%+-]?\s*[-+]?[0-9]+(?:\.[0-9]+)?)',
                },
                'good_practices': {
                    'docstrings': r'"""[\s\S]*?"""',
                    'type_hints': r'def\s+\w+\([^)]*: \w+[^)]*\)\s*->\s*\w+:',
                }
            },
            'java': {
                'code_smells': {
                    'long_method': r'(public|private|protected)?\s+\w+\s+\w+\([^)]*\)\s*{(?:(?!}).)*?(?:\n\s*\w+){20,}',
                    'too_many_parameters': r'\w+\s+\w+\((?:[^,]+,){5,}[^)]+\)\s*{',
                },
                'good_practices': {
                    'javadoc': r'/\*\*[\s\S]*?\*/',
                    'exception_handling': r'try\s*{[\s\S]*?}\s*catch\s*\([\s\S]*?\)\s*{',
                }
            }
        }
    
    def analyze(self, code: str, language: str) -> Dict[str, Dict[str, int]]:
        """Analyze code quality metrics"""
        results = {
            'code_smells': {},
            'good_practices': {}
        }
        
        lang_patterns = self.patterns.get(language, self.patterns.get('python'))
        
        # Check for code smells
        for smell_name, pattern in lang_patterns['code_smells'].items():
            matches = re.findall(pattern, code, re.DOTALL)
            results['code_smells'][smell_name] = len(matches)
        
        # Check for good practices
        for practice_name, pattern in lang_patterns['good_practices'].items():
            matches = re.findall(pattern, code, re.DOTALL)
            results['good_practices'][practice_name] = len(matches)
        
        return results

class SecurityScanner:
    """Scans code for security vulnerabilities with improved pattern detection"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'python': {
                'sql_injection': [
                    # String concatenation in SQL queries - direct execute calls
                    r'(cursor|connection|conn)\.execute\s*\(\s*[\'"][^\'")]*\+\s*\w+',
                    r'(cursor|connection|conn)\.execute\s*\(\s*[\'"][^\'")]*\s*%\s*\(',
                    r'(cursor|connection|conn)\.execute\s*\(\s*[\'"][^\'")]*\.format\s*\(',
                    # Variable assignment with string concatenation in SQL
                    r'query\s*=\s*[\'"][^\'")]*\'\s*\+\s*\w+\s*\+\s*[\'"][^\'")]*[\'"]',
                    r'query\s*=\s*[\'"][^\'")]*\+\s*\w+\s*\+[^\'")]*[\'"]',
                    r'query\s*=\s*[\'"][^\'")]*\'\s*\+\s*\w+',
                    # SELECT statements with concatenation
                    r'[\'"]SELECT\s+[^\'")]*\+\s*\w+[^\'")]*[\'"]',
                    r'[\'"]SELECT\s+[^\'")]*\'\s*\+\s*\w+\s*\+\s*\'[^\'")]*[\'"]',
                    # INSERT, UPDATE, DELETE with concatenation
                    r'[\'"]INSERT\s+[^\'")]*\'\s*\+\s*\w+',
                    r'[\'"]UPDATE\s+[^\'")]*\'\s*\+\s*\w+',
                    r'[\'"]DELETE\s+[^\'")]*\'\s*\+\s*\w+',
                    # Direct cursor.execute with variable
                    r'cursor\.execute\s*\(\s*\w+\s*\)',
                    # f-string SQL injections
                    r'f[\'"]SELECT\s+[^\'")]*\{\w+\}[^\'")]*[\'"]',
                    r'f[\'"][^\'")]*INSERT\s+[^\'")]*\{\w+\}[^\'")]*[\'"]',
                    # General SQL query patterns with + operator
                    r'[\'"][^\'")]*(?:SELECT|INSERT|UPDATE|DELETE)[^\'")]*[\'"][^+]*\+[^+]*\w+',
                    r'[\'"][^\'")]*WHERE[^\'")]*[\'"][^+]*\+[^+]*\w+[^+]*\+[^+]*[\'"]',
                ],
                'command_injection': [
                    r'os\.system\s*\(\s*[^)]*\+',
                    r'subprocess\.(call|run|Popen)\s*\(\s*[^)]*\+',
                    r'subprocess\.(call|run|Popen)\s*\(\s*f[\'"][^\'")]*\{',
                    r'exec\s*\(\s*[^)]*\+',
                    r'eval\s*\(\s*[^)]*\+',
                ],
                'insecure_deserialization': [
                    r'pickle\.loads\s*\(',
                    r'yaml\.load\s*\([^)]*\)',
                    r'eval\s*\(',
                    r'exec\s*\(',
                ],
                'hardcoded_credentials': [
                    r'password\s*=\s*[\'"][a-zA-Z0-9!@#$%^&*()_+=-]{6,}[\'"]',
                    r'api_key\s*=\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
                    r'token\s*=\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
                    r'secret\s*=\s*[\'"][a-zA-Z0-9]{10,}[\'"]',
                    r'key\s*=\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
                    r'[\'"]sk-[a-zA-Z0-9]{32,}[\'"]',  # OpenAI API keys
                    r'[\'"]ghp_[a-zA-Z0-9]{36}[\'"]',  # GitHub tokens
                ],
                'path_traversal': [
                    r'open\s*\(\s*[^)]*\+\s*\w+',
                    r'open\s*\(\s*f[\'"][^\'")]*\{',
                    r'open\s*\(\s*[\'"][^\'")]*\.\.[^\'")]*[\'"]',
                    r'os\.path\.join\s*\([^)]*\+',
                    r'filepath\s*=\s*[^+]*\+\s*\w+',
                    r'with\s+open\s*\(\s*[^)]*\+',
                ],
                'weak_crypto': [
                    r'md5\s*\(',
                    r'hashlib\.md5\s*\(',
                    r'sha1\s*\(',
                    r'hashlib\.sha1\s*\(',
                    r'random\.random\s*\(',
                    r'time\.time\s*\(\)\s*%',
                ],
            },
            'java': {
                'sql_injection': [
                    r'executeQuery\s*\(\s*[^)]*\+',
                    r'executeUpdate\s*\(\s*[^)]*\+',
                    r'prepareStatement\s*\(\s*[^)]*\+',
                    r'Statement\s*\.\s*execute\s*\(\s*[^)]*\+',
                ],
                'command_injection': [
                    r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    r'ProcessBuilder\s*\(',
                    r'new\s+ProcessBuilder\s*\(',
                ],
                'xxe': [
                    r'DocumentBuilderFactory\.newInstance\s*\(\)',
                    r'SAXParserFactory\.newInstance\s*\(\)',
                    r'XMLInputFactory\.newInstance\s*\(\)',
                ],
                'insecure_random': [
                    r'new\s+Random\s*\(',
                    r'Math\.random\s*\(',
                ],
                'path_traversal': [
                    r'new\s+File\s*\(\s*[^)]*\+',
                    r'new\s+FileInputStream\s*\(\s*[^)]*\+',
                    r'Files\.readAllBytes\s*\(\s*Paths\.get\s*\([^)]*\+',
                ],
                'hardcoded_credentials': [
                    r'password\s*=\s*[\'"][a-zA-Z0-9!@#$%^&*()_+=-]{6,}[\'"]',
                    r'apiKey\s*=\s*[\'"][a-zA-Z0-9]{20,}[\'"]',
                    r'secretKey\s*=\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
                ],
            },
            'javascript': {
                'sql_injection': [
                    r'query\s*\(\s*[\'"`][^\'"`]*\+',
                    r'execute\s*\(\s*[\'"`][^\'"`]*\+',
                    r'\.query\s*\(\s*`[^`]*\$\{',
                ],
                'command_injection': [
                    r'exec\s*\(\s*[^)]*\+',
                    r'spawn\s*\(\s*[^)]*\+',
                    r'eval\s*\(\s*[^)]*\+',
                ],
                'xss': [
                    r'innerHTML\s*=\s*[^;]*\+',
                    r'document\.write\s*\(\s*[^)]*\+',
                    r'outerHTML\s*=\s*[^;]*\+',
                ],
                'hardcoded_credentials': [
                    r'password\s*[:=]\s*[\'"`][a-zA-Z0-9!@#$%^&*()_+=]{6,}[\'"`]',
                    r'apiKey\s*[:=]\s*[\'"`][a-zA-Z0-9]{20,}[\'"`]',
                    r'token\s*[:=]\s*[\'"`][a-zA-Z0-9]{20,}[\'"`]',
                ],
            }
        }
    
    def scan(self, code: str, language: str) -> Dict[str, List[str]]:
        """Scan code for security vulnerabilities with detailed detection"""
        vulnerabilities = {}
        lang_patterns = self.vulnerability_patterns.get(language.lower(), {})
        
        if not lang_patterns:
            return {"message": "Security scanning not available for this language"}
        
        for vuln_name, patterns in lang_patterns.items():
            matches = []
            pattern_list = patterns if isinstance(patterns, list) else [patterns]
            
            for pattern in pattern_list:
                found_matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in found_matches:
                    line_num = code[:match.start()].count('\n') + 1
                    match_text = match.group(0)[:50] + ("..." if len(match.group(0)) > 50 else "")
                    matches.append(f"Line {line_num}: {match_text}")
            
            if matches:
                vulnerabilities[vuln_name] = matches
        
        return vulnerabilities

def visualize_code_execution(code: str, language: str) -> Dict[str, Any]:
    """Create interactive code execution visualization with security checks"""
    
    # Enhanced security check for cloud deployment and restricted environments
    is_cloud = any([
        "streamlit.io" in os.environ.get("HOSTNAME", ""),
        "STREAMLIT_SHARING" in os.environ,
        "STREAMLIT_CLOUD" in os.environ,
        os.environ.get("DYNO"),  # Heroku
        os.environ.get("RAILWAY_ENVIRONMENT"),  # Railway
        os.environ.get("VERCEL"),  # Vercel
        os.environ.get("NETLIFY"),  # Netlify
    ])
    
    if is_cloud:
        return {
            "message": "Code execution visualization is disabled in cloud deployment for security reasons",
            "steps": [{"type": "info", "content": "Code execution is restricted in cloud environments to prevent security risks"}],
            "success": False
        }
    
    if language != 'python':
        return {"message": "Code visualization only available for Python"}
    
    # Enhanced security check for dangerous operations
    dangerous_patterns = [
        r'import\s+os\s*$',
        r'import\s+subprocess\s*$',
        r'import\s+sys\s*$',
        r'__import__\s*\(',
        r'exec\s*\(',
        r'eval\s*\(',
        r'open\s*\(',
        r'file\s*\(',
        r'input\s*\(',
        r'raw_input\s*\(',
        r'compile\s*\(',
        r'globals\s*\(',
        r'locals\s*\(',
        r'vars\s*\(',
        r'dir\s*\(',
        r'hasattr\s*\(',
        r'getattr\s*\(',
        r'setattr\s*\(',
        r'delattr\s*\(',
        r'__.*__',
        r'quit\s*\(',
        r'exit\s*\(',
        r'while\s+True\s*:',  # Prevent infinite loops
        r'for.*while.*:',     # Nested loop patterns that might be infinite
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
            return {
                "message": "Code execution blocked: potentially dangerous operations detected",
                "steps": [{"type": "error", "content": f"Blocked due to security policy"}],
                "success": False
            }
    
    # Additional length and complexity checks
    if len(code) > 5000:  # Reduced limit for better performance
        return {
            "message": "Code execution blocked: code too long (>5000 characters)",
            "steps": [{"type": "error", "content": "Code exceeds maximum allowed length"}],
            "success": False
        }
    
    if code.count('\n') > 200:  # Reduced limit for better performance
        return {
            "message": "Code execution blocked: too many lines (>200)",
            "steps": [{"type": "error", "content": "Code exceeds maximum allowed lines"}],
            "success": False
        }
    
    # Try in-process execution first (safer and more reliable)
    try:
        return _execute_code_in_process(code)
    except Exception as in_process_error:
        # Fallback to subprocess execution if in-process fails
        try:
            return _execute_code_subprocess(code)
        except Exception as subprocess_error:
            return {
                "message": "Code execution failed - both in-process and subprocess methods encountered errors",
                "steps": [
                    {"type": "error", "content": f"In-process error: {str(in_process_error)}"},
                    {"type": "error", "content": f"Subprocess error: {str(subprocess_error)}"}
                ],
                "success": False
            }

def _execute_code_in_process(code: str) -> Dict[str, Any]:
    """Execute code in the current process with output capture"""
    from io import StringIO
    import contextlib
    
    # Create a string buffer to capture output
    output_buffer = StringIO()
    error_buffer = StringIO()
    
    try:
        # Capture stdout and stderr
        with contextlib.redirect_stdout(output_buffer), contextlib.redirect_stderr(error_buffer):
            # Create a restricted execution environment
            # Create a restricted execution environment
            restricted_globals = {
                '__builtins__': {
                    'print': print,
                    'len': len,
                    'range': range,
                    'str': str,
                    'int': int,
                    'float': float,
                    'list': list,
                    'dict': dict,
                    'tuple': tuple,
                    'set': set,
                    'bool': bool,
                    'abs': abs,
                    'max': max,
                    'min': min,
                    'sum': sum,
                    'sorted': sorted,
                    'reversed': reversed,
                    'enumerate': enumerate,
                    'zip': zip,
                    'map': map,
                    'filter': filter,
                    'any': any,
                    'all': all,
                    '__import__': __import__,
                },
                # Add commonly used safe modules
                'time': __import__('time'),
                'math': __import__('math'),
                'random': __import__('random'),
                'datetime': __import__('datetime'),
                'collections': __import__('collections'),
            }
            # Execute the code
            exec(code, restricted_globals, {})
        
        # Get the captured output
        stdout_content = output_buffer.getvalue()
        stderr_content = error_buffer.getvalue()
        
        steps = []
        if stdout_content:
            steps.append({"type": "section", "content": "=== Code Output ==="})
            for line in stdout_content.split('\n'):
                if line.strip():
                    steps.append({"type": "output", "content": line})
        
        if stderr_content:
            steps.append({"type": "error", "content": "=== Errors ==="})
            for line in stderr_content.split('\n'):
                if line.strip():
                    steps.append({"type": "error", "content": line})
        
        if not steps:
            steps.append({"type": "info", "content": "Code executed successfully (no output)"})
        
        return {
            "steps": steps,
            "raw_output": stdout_content + stderr_content if stdout_content or stderr_content else "No output generated",
            "success": True
        }
        
    except Exception as e:
        return {
            "steps": [
                {"type": "error", "content": "=== Execution Error ==="},
                {"type": "error", "content": f"Error: {str(e)}"}
            ],
            "raw_output": f"Execution failed: {str(e)}",
            "success": False
        }

def _execute_code_subprocess(code: str) -> Dict[str, Any]:
    """Fallback subprocess execution with enhanced error handling"""
    temp_path = None
    try:
        # Create a temporary file to run the code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as temp:
            # Create safer instrumented code
            instrumented_code = f"""
import sys
import traceback
from io import StringIO

# Disable hash randomization issues
import os
os.environ['PYTHONHASHSEED'] = '0'

# Capture stdout
original_stdout = sys.stdout
output_buffer = StringIO()
sys.stdout = output_buffer

try:
    # Original code execution
{textwrap.indent(code, '    ')}
    
    # Capture the output
    execution_output = output_buffer.getvalue()
    sys.stdout = original_stdout
    print("=== EXECUTION OUTPUT ===")
    if execution_output:
        print(execution_output)
    else:
        print("Code executed successfully (no output)")
        
except Exception as exec_error:
    sys.stdout = original_stdout
    print(f"=== EXECUTION ERROR ===")
    print(f"Error: {{str(exec_error)}}")
    print("=== TRACEBACK ===")
    traceback.print_exc()
finally:
    sys.stdout = original_stdout
            """
            temp.write(instrumented_code)
            temp_path = temp.name
        
        # Enhanced environment setup to prevent hash randomization issues
        env = os.environ.copy()
        env.update({
            'PYTHONHASHSEED': '0',  # Disable hash randomization
            'PYTHONIOENCODING': 'utf-8',  # Ensure proper encoding
            'PYTHONUNBUFFERED': '1',  # Ensure output is not buffered
            'PYTHONDONTWRITEBYTECODE': '1',  # Don't create .pyc files
        })
        
        # Remove potentially problematic environment variables
        for key in ['PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONOPTIMIZE']:
            env.pop(key, None)
        
        # Run the instrumented code with enhanced configuration
        result = subprocess.run(
            [sys.executable, '-u', temp_path],  # -u for unbuffered output
            capture_output=True, 
            text=True, 
            timeout=5,  # Reduced timeout for better responsiveness
            env=env,
            cwd=tempfile.gettempdir()  # Use temp directory as working directory
        )
        
        # Parse the output
        output = result.stdout + result.stderr
        if not output.strip():
            output = "No output generated"
        
        # Create execution steps from the output
        steps = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if line:
                if "EXECUTION OUTPUT" in line:
                    steps.append({"type": "section", "content": "=== Code Output ==="})
                elif "EXECUTION ERROR" in line:
                    steps.append({"type": "error", "content": "=== Execution Error ==="})
                elif "TRACEBACK" in line:
                    steps.append({"type": "error", "content": "=== Error Details ==="})
                elif line.startswith("Error:"):
                    steps.append({"type": "error", "content": line})
                elif line and not line.startswith("==="):
                    steps.append({"type": "output", "content": line})
        
        # If no steps were created, add a default step
        if not steps:
            steps.append({"type": "info", "content": "Code executed without visible output"})
        
        return {
            "steps": steps,
            "raw_output": output,
            "success": result.returncode == 0
        }
        
    except subprocess.TimeoutExpired:
        return {"error": "Code execution timed out (maximum 5 seconds allowed)"}
    except Exception as visualization_error:
        return {"error": f"Error in code visualization: {str(visualization_error)}"}
    finally:
        # Clean up temporary file
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass  # Ignore cleanup errors

def generate_refactoring_suggestions(analyzer, code: str, language: str, complexity: int, details: Dict) -> Dict[str, str]:
    """Generate specific refactoring suggestions using Gemini AI"""
    if not analyzer.model:
        return {"message": "API key required for refactoring suggestions"}
    
    try:
        # Identify the biggest complexity contributors
        complexity_contributors = sorted(details.items(), key=lambda x: x[1], reverse=True)
        top_contributors = complexity_contributors[:3]
        
        prompt = f"""
        You are a Senior Software Engineer specializing in code quality and maintainability, and also in Data Structures and Algorithms.
        I have {language} code with cyclomatic complexity of {complexity}. 
        The main complexity contributors are: 
        {', '.join([f"{item[0]} ({item[1]} occurrences)" for item in top_contributors])}
        
        Code:
        ```{language}
        {code}
        ```
        
        Provide specific, actionable refactoring suggestions to reduce complexity:
        1. Identify the most complex parts of the code
        2. Suggest specific design patterns or techniques applicable to this code
        3. Provide 2-3 concrete code examples showing before/after refactoring
        4. Explain how each refactoring improves maintainability
        
        Format with clear sections and code examples in markdown.
        """
        
        response = analyzer.model.generate_content(prompt)
        return {"suggestions": response.text}
    except Exception as e:
        return {"error": f"Failed to generate refactoring suggestions: {str(e)}"}

def estimate_performance(analyzer, code: str, language: str) -> Dict[str, Any]:
    """Estimate code performance characteristics"""
    try:
        if language not in ['python', 'java', 'javascript', 'typescript', 'jsx', 'tsx']:
            return {"message": "Performance estimation not available for this language"}
        
        # Count loops and identify nested loops - updated patterns for JS/TS/React
        if language in ['javascript', 'typescript', 'jsx', 'tsx']:
            single_loops = len(re.findall(r'\b(for|while|forEach|map|filter|reduce)\b', code))
            nested_loops = len(re.findall(r'\b(for|while)\b[^{]*?{[^}]*?\b(for|while)\b', code, re.DOTALL))
            # Check for React specific patterns
            react_renders = len(re.findall(r'\.map\([^)]*?\)\s*.*?{[^}]*?return', code, re.DOTALL))
            if react_renders > 0:
                single_loops += react_renders
        else:
            single_loops = len(re.findall(r'\b(for|while)\b', code))
            nested_loops = len(re.findall(r'\b(for|while)\b[^{]*?{[^}]*?\b(for|while)\b', code, re.DOTALL))
        
        recursion = len(re.findall(r'function\s+(\w+)[^{]*?{[^}]*?\1\s*\(', code, re.DOTALL))
        
        # Estimate algorithmic complexity
        if nested_loops > 1:
            big_o = "O(n²) or higher"
            efficiency = "Low"
        elif nested_loops == 1:
            big_o = "O(n²)"
            efficiency = "Moderate"
        elif single_loops > 0:
            big_o = "O(n)"
            efficiency = "Good"
        elif recursion > 0:
            big_o = "Potentially O(2ⁿ) - recursive"
            efficiency = "Potentially problematic"
        else:
            big_o = "O(1) or O(log n)"
            efficiency = "Excellent"
        
        return {
            "estimated_big_o": big_o,
            "efficiency_rating": efficiency,
            "loop_count": single_loops,
            "nested_loops": nested_loops,
            "recursion_detected": recursion > 0
        }
    except Exception as e:
        return {"error": f"Error in performance estimation: {str(e)}"}

class CodeAnalyzer:
    """Main code analyzer class"""
    
    def __init__(self, api_key: str):
        self.complexity_analyzer = CyclomaticComplexityAnalyzer()
        if api_key:
            genai.configure(api_key=api_key)
            # Use the correct model name for Gemini
            self.model = genai.GenerativeModel('gemini-1.5-flash')
        else:
            self.model = None
    
    def detect_language(self, filename: str, code: str) -> str:
        """Detect programming language from filename and code"""
        extension = filename.split('.')[-1].lower()
        
        language_map = {
            'py': 'python',
            'java': 'java',
            'js': 'javascript',
            'cpp': 'cpp',
            'c': 'c',
            'cs': 'csharp',
            'php': 'php',
            'rb': 'ruby',
            'go': 'go'
        }
        
        return language_map.get(extension, 'unknown')
    
    def calculate_bug_probability(self, complexity: int) -> Tuple[str, str]:
        """Calculate bug probability based on complexity"""
        if complexity <= 10:
            return "Low", "🟢"
        elif complexity <= 20:
            return "Medium", "🟡"
        elif complexity <= 50:
            return "High", "🟠"
        else:
            return "Very High", "🔴"
    
    def generate_flowchart_with_ai(self, code: str, language: str) -> str:
        """Generate intelligent flowchart using Gemini AI"""
        if not self.model:
            return self._generate_fallback_flowchart(code, language)
        
        try:
            prompt = f"""
            You are a Senior Software Engineer specializing in code quality and maintainability, and also in Data Structures and Algorithms.
            Analyze this {language} code and generate a clean, readable Graphviz DOT notation flowchart.
            
            Code to analyze:
            ```{language}
            {code}
            ```
            
            Requirements:
            1. Create a simplified, high-level flowchart showing the main logic flow
            2. Use appropriate shapes: ellipse for start/end, diamond for decisions, box for processes
            3. Keep node labels concise (max 20 chars) and meaningful
            4. Group related operations to avoid too many nodes
            5. Use proper colors: lightgreen for start/end, lightyellow for decisions, lightblue for processes
            6. Focus on the main control flow, not every single statement
            7. Maximum 15 nodes for readability
            8. Use clear, descriptive labels
            9. It should be made such that user can understand flow of entire code
            
            Return ONLY the DOT notation code without any explanation or markdown formatting.
            
            Example format:
            digraph {{
                rankdir=TB;
                node [shape=box, style="rounded,filled", fontname="Arial", fontsize=10];
                edge [fontname="Arial", fontsize=9];
                
                start [label="START", shape=ellipse, fillcolor=lightgreen];
                // ... other nodes
                end [label="END", shape=ellipse, fillcolor=lightgreen];
            }}
            """
            
            response = self.model.generate_content(prompt)
            dot_code = response.text.strip()
            
            # Clean up the response - remove markdown code blocks if present
            if '```dot' in dot_code:
                dot_code = dot_code.split('```dot')[1].split('```')[0].strip()
            elif '```' in dot_code:
                dot_code = dot_code.split('```')[1].split('```')[0].strip()
            
            # Validate that it's proper DOT notation
            if 'digraph' in dot_code and '{' in dot_code and '}' in dot_code:
                return dot_code
            else:
                st.warning("AI generated invalid flowchart, using fallback method")
                return self._generate_fallback_flowchart(code, language)
                
        except Exception as e:
            st.warning(f"AI flowchart generation failed: {str(e)}, using fallback method")
            return self._generate_fallback_flowchart(code, language)
    
    def _generate_fallback_flowchart(self, code: str, language: str) -> str:
        """Generate a simple, clean fallback flowchart"""
        lines = [line.strip() for line in code.split('\n') if line.strip() and not line.strip().startswith('#')]
        
        # Limit to prevent overcrowding
        if len(lines) > 20:
            lines = lines[:20]
        
        dot = graphviz.Digraph(comment='Code Flow')
        dot.attr(rankdir='TB', size='10,8', dpi='200')
        dot.attr('node', shape='box', style='filled,rounded', fontname='Arial', fontsize='10')
        dot.attr('edge', fontname='Arial', fontsize='9')
        
        # Start node
        dot.node('start', 'START', shape='ellipse', fillcolor='lightgreen')
        
        # Identify key constructs
        key_constructs = []
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            if any(keyword in line_lower for keyword in ['def ', 'function ', 'class ']):
                name = line.split('(')[0].split('{')[0].replace('def ', '').replace('function ', '').replace('class ', '').strip()
                key_constructs.append(('function', f"Function: {name[:15]}", 'lightcyan'))
            elif line_lower.startswith('if ') or ' if ' in line_lower:
                condition = line.replace('if ', '').replace(':', '').replace('{', '').strip()[:15]
                key_constructs.append(('decision', f"If {condition}?", 'lightyellow'))
            elif line_lower.startswith('for ') or line_lower.startswith('while '):
                loop_type = 'For' if 'for' in line_lower else 'While'
                key_constructs.append(('decision', f"{loop_type} loop", 'lightyellow'))
            elif 'return' in line_lower:
                key_constructs.append(('process', 'Return', 'lightcoral'))
        
        # If no key constructs found, create a simple process flow
        if not key_constructs:
            dot.node('process', 'Process Code', fillcolor='lightblue')
            dot.edge('start', 'process')
            prev_node = 'process'
        else:
            # Create nodes for key constructs
            prev_node = 'start'
            for i, (node_type, label, color) in enumerate(key_constructs[:8]):  # Limit to 8 nodes
                node_id = f"node_{i}"
                shape = 'diamond' if node_type == 'decision' else 'box'
                dot.node(node_id, label, shape=shape, fillcolor=color)
                dot.edge(prev_node, node_id)
                prev_node = node_id
        
        # End node
        dot.node('end', 'END', shape='ellipse', fillcolor='lightgreen')
        dot.edge(prev_node, 'end')
        
        return dot.source
    
    def analyze_with_gemini(self, code: str, language: str) -> Dict[str, str]:
        """Use Gemini AI to analyze code"""
        if not self.model:
            return {key: "API key not provided" for key in ['summary', 'pseudocode', 'time_complexity', 'space_complexity', 'execution_flow']}
            
        try:
            prompts = {
                'summary': f"""
                You are Codelytics Syntactica, a Senior Software Engineer specializing in code quality and maintainability, and also in Data Structures and Algorithms and Problem Solving.
                You are an expert code analyst.
                Analyze this {language} code and provide a concise complete summary of what it does and its main functionality:
                
                ```{language}
                {code}
                ```
                
                Provide a clear, technical summary in 2-3 sentences.
                """,
                
                'pseudocode': f"""
                Convert this {language} code into clear, well-formatted pseudocode:
                
                ```{language}
                {code}
                ```
                
                Requirements:
                - Use proper indentation and structure
                - Use clear, descriptive variable names
                - Include comments for complex logic
                - Format as readable pseudocode, not natural language
                - Use markdown formatting with proper code blocks
                
                Format your response as:
                ```
                BEGIN ProgramName
                    // Your pseudocode here
                END ProgramName
                ```
                """,
                
                'time_complexity': f"""
                Analyze the time complexity of this {language} code:
                
                ```{language}
                {code}
                ```
                
                Provide the Big O time complexity with a clear explanation of why.
                """,
                
                'space_complexity': f"""
                Analyze the space complexity of this {language} code:
                
                ```{language}
                {code}
                ```
                
                Provide the Big O space complexity with a clear explanation of the memory usage.
                """,
                
                'execution_flow': f"""
                Explain the execution flow of this {language} code with example dry run:
                
                ```{language}
                {code}
                ```
                
                Describe how the code executes step by step in a clear, structured manner. If it is simple code, explain how it runs on machine and how each function is called. If it is a complex code, provide a detailed explanation of execution and general flow.
                If it is a Data Structures and Algorithms problem, provide a logic to approach problem and dry run with example inputs and outputs.
                If it is Software Engineering code, provide how it runs and what it does step by step in backend and for user.
                """
            }
            
            results = {}
            for key, prompt in prompts.items():
                try:
                    response = self.model.generate_content(prompt)
                    results[key] = response.text
                except Exception as e:
                    results[key] = f"Error analyzing {key}: {str(e)}"
            
            return results
        except Exception as e:
            return {key: f"Error: {str(e)}" for key in ['summary', 'pseudocode', 'time_complexity', 'space_complexity', 'execution_flow']}

def generate_class_hierarchy(code: str, language: str) -> str:
    """Generate class hierarchy diagram showing inheritance relationships"""
    # Try Gemini AI first for better diagram generation
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are a Senior Software Engineer specializing in software architecture and UML diagrams.
            Analyze this {language} code and generate a clean, well-structured class hierarchy diagram in Graphviz DOT notation.
            
            Code to analyze:
            ```{language}
            {code}
            ```
            
            Requirements:
            1. Show all classes and their inheritance relationships
            2. Use proper UML notation: empty arrowheads for inheritance
            3. Different colors: lightblue for concrete classes, lightgreen for interfaces/abstract classes
            4. Include class names and key relationships
            5. Use proper Graphviz syntax with clear node and edge definitions
            6. If no classes found, create a simple informational node
            
            Return ONLY the DOT notation code without any explanation or markdown formatting.
            
            Example format:
            digraph {{
                rankdir=BT;
                node [shape=box, style="filled,rounded", fontname="Arial"];
                edge [arrowhead=empty, color="#2c3e50"];
                
                // Class nodes
                "ClassName" [fillcolor=lightblue];
                // Inheritance edges
                "Child" -> "Parent";
            }}
            """
            
            response = model.generate_content(prompt)
            dot_code = response.text.strip()
            
            # Clean up the response
            if '```dot' in dot_code:
                dot_code = dot_code.split('```dot')[1].split('```')[0].strip()
            elif '```' in dot_code:
                dot_code = dot_code.split('```')[1].split('```')[0].strip()
            
            # Validate that it's proper DOT notation
            if 'digraph' in dot_code and '{' in dot_code and '}' in dot_code:
                return dot_code
    except Exception as e:
        pass  # Fall back to manual generation
    
    # Fallback to manual generation
    dot = graphviz.Digraph(comment='Class Hierarchy')
    dot.attr(rankdir='BT', size='10,10', dpi='300')
    dot.attr('node', shape='box', style='filled,rounded', fillcolor='lightblue', fontname='Arial')
    dot.attr('edge', arrowhead='empty', color='#2c3e50')
    
    classes = {}
    inheritance = []
    
    if language == 'python':
        class_pattern = r'class\s+(\w+)(?:\(([^)]+)\))?:'
        matches = re.findall(class_pattern, code)
        
        for match in matches:
            class_name = match[0]
            parent_classes = match[1].split(',') if match[1] else []
            
            classes[class_name] = True
            dot.node(class_name, f"{class_name}")
            
            for parent in parent_classes:
                parent = parent.strip()
                if parent and parent != 'object':
                    inheritance.append((class_name, parent))
    elif language == 'java':
        try:
            tree = javalang.parse.parse(code)
            for path, node in tree:
                if isinstance(node, javalang.tree.ClassDeclaration):
                    class_name = node.name
                    classes[class_name] = True
                    dot.node(class_name, f"{class_name}")
                    
                    if node.extends:
                        parent = node.extends.name
                        inheritance.append((class_name, parent))
                elif isinstance(node, javalang.tree.InterfaceDeclaration):
                    interface_name = node.name
                    classes[interface_name] = True
                    dot.node(interface_name, f"«interface»\\n{interface_name}", fillcolor='lightgreen')
        except:
            pass
    
    # Add inheritance edges
    for child, parent in inheritance:
        if parent not in classes:
            classes[parent] = True
            dot.node(parent, parent)
        dot.edge(child, parent)
    
    if not classes:
        dot.node('no_classes', 'No classes detected in code', shape='note', fillcolor='lightyellow')
    
    return dot.source

def generate_call_graph(code: str, language: str) -> str:
    """Generate function call graph showing dependencies between functions"""
    # Try Gemini AI first for better diagram generation
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are a Senior Software Engineer specializing in code analysis and software architecture.
            Analyze this {language} code and generate a function call graph in Graphviz DOT notation showing which functions call which other functions.
            
            Code to analyze:
            ```{language}
            {code}
            ```
            
            Requirements:
            1. Show all functions/methods as nodes
            2. Show function calls as directed edges
            3. Use clear, readable labels
            4. Color coding: lightblue for regular functions, lightgreen for main/entry functions
            5. Use proper Graphviz syntax
            6. Limit to maximum 20 nodes for readability
            7. If no functions found, create an informational node
            
            Return ONLY the DOT notation code without any explanation or markdown formatting.
            
            Example format:
            digraph {{
                rankdir=LR;
                node [shape=box, style="filled,rounded", fontname="Arial"];
                edge [arrowhead=vee, color="#2c3e50"];
                
                "function1" [fillcolor=lightblue];
                "function2" [fillcolor=lightblue];
                "function1" -> "function2" [label="calls"];
            }}
            """
            
            response = model.generate_content(prompt)
            dot_code = response.text.strip()
            
            # Clean up the response
            if '```dot' in dot_code:
                dot_code = dot_code.split('```dot')[1].split('```')[0].strip()
            elif '```' in dot_code:
                dot_code = dot_code.split('```')[1].split('```')[0].strip()
            
            if 'digraph' in dot_code and '{' in dot_code and '}' in dot_code:
                return dot_code
    except Exception as e:
        pass
    
    # Fallback to manual generation
    dot = graphviz.Digraph(comment='Function Call Graph')
    dot.attr(rankdir='LR', size='12,10', dpi='300')
    dot.attr('node', shape='box', style='filled,rounded', fillcolor='lightblue', fontname='Arial')
    dot.attr('edge', arrowhead='vee', color='#2c3e50')
    
    functions = set()
    calls = []
    
    if language == 'python':
        func_pattern = r'def\s+(\w+)\s*\('
        func_matches = re.findall(func_pattern, code)
        
        for func_name in func_matches:
            functions.add(func_name)
            color = 'lightgreen' if func_name == 'main' else 'lightblue'
            dot.node(func_name, func_name, fillcolor=color)
        
        # Simple call detection
        for line in code.split('\n'):
            for func_name in func_matches:
                if f'{func_name}(' in line and not line.strip().startswith('def'):
                    for other_func in func_matches:
                        if f'def {other_func}' in code.split(line)[0]:
                            calls.append((other_func, func_name))
                            break
    
    # Add call edges
    for caller, callee in calls:
        if caller != callee:  # Avoid self-loops
            dot.edge(caller, callee, label="calls")
    
    if not functions:
        dot.node('no_functions', 'No functions detected in code', shape='note', fillcolor='lightyellow')
    
    return dot.source

def generate_control_flow_graph(code: str, language: str) -> str:
    """Generate detailed control flow graph showing branching and loops"""
    # Try Gemini AI first for better diagram generation
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are a Senior Software Engineer specializing in program analysis and control flow visualization.
            Analyze this {language} code and generate a control flow graph in Graphviz DOT notation showing the execution paths.
            
            Code to analyze:
            ```{language}
            {code}
            ```
            
            Requirements:
            1. Show all control structures: if/else, loops, function calls
            2. Use diamonds for decision points, boxes for statements, ellipses for start/end
            3. Color coding: lightgreen for start/end, lightyellow for decisions, lightblue for processes
            4. Clear, concise labels (max 25 characters per node)
            5. Show True/False paths for conditions
            6. Use proper Graphviz syntax with rankdir=TB
            7. Maximum 15 nodes for readability
            8. If code is too complex, show high-level flow only
            
            Return ONLY the DOT notation code without any explanation or markdown formatting.
            
            Example format:
            digraph {{
                rankdir=TB;
                node [shape=box, style="filled,rounded", fontname="Arial"];
                
                start [label="START", shape=ellipse, fillcolor=lightgreen];
                decision [label="condition?", shape=diamond, fillcolor=lightyellow];
                start -> decision;
                decision -> process1 [label="True"];
                decision -> process2 [label="False"];
            }}
            """
            
            response = model.generate_content(prompt)
            dot_code = response.text.strip()
            
            # Clean up the response
            if '```dot' in dot_code:
                dot_code = dot_code.split('```dot')[1].split('```')[0].strip()
            elif '```' in dot_code:
                dot_code = dot_code.split('```')[1].split('```')[0].strip()
            
            if 'digraph' in dot_code and '{' in dot_code and '}' in dot_code:
                return dot_code
    except Exception as e:
        pass
    
    # Fallback to manual generation
    dot = graphviz.Digraph(comment='Control Flow Graph')
    dot.attr(rankdir='TB', size='10,12', dpi='300')
    dot.attr('node', shape='box', style='filled,rounded', fontname='Arial', fontsize='10')
    
    # Simple control flow for basic structures
    lines = [line.strip() for line in code.split('\n') if line.strip()]
    
    dot.node('start', 'START', shape='ellipse', fillcolor='lightgreen')
    
    prev_node = 'start'
    node_count = 0
    
    for i, line in enumerate(lines[:10]):  # Limit to 10 lines
        node_count += 1
        node_id = f'node_{node_count}'
        
        if line.startswith('if ') or ' if ' in line:
            condition = line.replace('if ', '').replace(':', '').strip()[:20]
            dot.node(node_id, f"If {condition}?", shape='diamond', fillcolor='lightyellow')
            dot.edge(prev_node, node_id)
            
            # Create true/false branches
            true_id = f'true_{node_count}'
            false_id = f'false_{node_count}'
            dot.node(true_id, 'True branch', fillcolor='lightgreen')
            dot.node(false_id, 'False branch', fillcolor='lightcoral')
            dot.edge(node_id, true_id, label='True')
            dot.edge(node_id, false_id, label='False')
            prev_node = true_id
            
        elif line.startswith('for ') or line.startswith('while '):
            loop_type = 'For' if line.startswith('for') else 'While'
            dot.node(node_id, f"{loop_type} loop", fillcolor='lightsalmon')
            dot.edge(prev_node, node_id)
            prev_node = node_id
            
        else:
            # Regular statement
            label = line[:20] + "..." if len(line) > 20 else line
            dot.node(node_id, label, fillcolor='lightblue')
            dot.edge(prev_node, node_id)
            prev_node = node_id
    
    # End node
    dot.node('end', 'END', shape='ellipse', fillcolor='lightgreen')
    dot.edge(prev_node, 'end')
    
    return dot.source

def generate_package_dependency_graph(code: str, language: str) -> str:
    """Generate package/module dependency graph showing imports"""
    # Try Gemini AI first for better diagram generation
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are a Senior Software Engineer specializing in software architecture and dependency analysis.
            Analyze this {language} code and generate a package/module dependency graph in Graphviz DOT notation showing all imports and dependencies.
            
            Code to analyze:
            ```{language}
            {code}
            ```
            
            Requirements:
            1. Show current module/class and all imported modules/packages
            2. Use arrows to show import relationships
            3. Color coding: lightblue for current module, lightgreen for standard libraries, lightyellow for third-party
            4. Group related imports when possible
            5. Use clear, readable labels
            6. Use proper Graphviz syntax with rankdir=LR
            7. If no imports found, create an informational node
            
            Return ONLY the DOT notation code without any explanation or markdown formatting.
            
            Example format:
            digraph {{
                rankdir=LR;
                node [shape=box, style="filled,rounded", fontname="Arial"];
                edge [arrowhead=vee, color="#2c3e50"];
                
                "Current Module" [fillcolor=lightblue];
                "os" [fillcolor=lightgreen];
                "Current Module" -> "os" [label="imports"];
            }}
            """
            
            response = model.generate_content(prompt)
            dot_code = response.text.strip()
            
            # Clean up the response
            if '```dot' in dot_code:
                dot_code = dot_code.split('```dot')[1].split('```')[0].strip()
            elif '```' in dot_code:
                dot_code = dot_code.split('```')[1].split('```')[0].strip()
            
            if 'digraph' in dot_code and '{' in dot_code and '}' in dot_code:
                return dot_code
    except Exception as e:
        pass
    
    # Fallback to manual generation
    dot = graphviz.Digraph(comment='Package Dependencies')
    dot.attr(rankdir='LR', size='11,8', dpi='300')
    dot.attr('node', shape='box', style='filled,rounded', fontname='Arial')
    dot.attr('edge', arrowhead='vee', color='#2c3e50')
    
    current_module = "Current Module"
    dot.node(current_module, current_module, fillcolor='lightblue', fontsize='12')
    
    imports = set()
    
    if language == 'python':
        import_patterns = [
            r'import\s+([\w.]+)',
            r'from\s+([\w.]+)\s+import'
        ]
        
        for pattern in import_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                imports.add(match)
    
    elif language == 'java':
        import_pattern = r'import\s+([\w.]+);'
        matches = re.findall(import_pattern, code)
        for match in matches:
            imports.add(match)
    
    # Add import nodes and edges
    for imp in imports:
        # Determine color based on common patterns
        if imp in ['os', 'sys', 'json', 'math', 'random', 'datetime', 'collections']:
            color = 'lightgreen'  # Standard library
        elif '.' in imp:
            color = 'lightyellow'  # Third-party or submodule
        else:
            color = 'lightcyan'   # Simple module
        
        dot.node(imp, imp, fillcolor=color)
        dot.edge(current_module, imp, label="imports")
    
    if not imports:
        dot.node('no_imports', 'No imports detected in code', shape='note', fillcolor='lightyellow')
    
    return dot.source

def generate_data_flow_diagram(code: str, language: str) -> str:
    """Generate data flow diagram showing variable assignments and usage"""
    # Try Gemini AI first for better diagram generation
    try:
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            prompt = f"""
            You are a Senior Software Engineer specializing in program analysis and data flow visualization.
            Analyze this {language} code and generate a data flow diagram in Graphviz DOT notation showing how data moves through variables.
            
            Code to analyze:
            ```{language}
            {code}
            ```
            
            Requirements:
            1. Show variables as ellipses, operations as rectangles
            2. Show data flow with arrows from source to destination
            3. Color coding: lightblue for variables, lightgreen for inputs, lightyellow for operations
            4. Include variable assignments, function calls, and data transformations
            5. Use clear, concise labels
            6. Use proper Graphviz syntax with rankdir=LR
            7. Maximum 12 nodes for readability
            8. If no significant data flow, create a simple informational node
            
            Return ONLY the DOT notation code without any explanation or markdown formatting.
            
            Example format:
            digraph {{
                rankdir=LR;
                node [fontname="Arial"];
                
                input [label="Input", shape=ellipse, fillcolor=lightgreen, style=filled];
                var1 [label="variable", shape=ellipse, fillcolor=lightblue, style=filled];
                op1 [label="operation", shape=box, fillcolor=lightyellow, style=filled];
                input -> op1 -> var1;
            }}
            """
            
            response = model.generate_content(prompt)
            dot_code = response.text.strip()
            
            # Clean up the response
            if '```dot' in dot_code:
                dot_code = dot_code.split('```dot')[1].split('```')[0].strip()
            elif '```' in dot_code:
                dot_code = dot_code.split('```')[1].split('```')[0].strip()
            
            if 'digraph' in dot_code and '{' in dot_code and '}' in dot_code:
                return dot_code
    except Exception as e:
        pass
    
    # Fallback to manual generation
    dot = graphviz.Digraph(comment='Data Flow')
    dot.attr(rankdir='LR', size='12,10', dpi='300')
    dot.attr('node', fontname='Arial')
    
    # Simple variable tracking
    variables = set()
    assignments = []
    
    if language == 'python':
        # Find assignments
        assignment_pattern = r'(\w+)\s*=\s*([^=\n]+)'
        matches = re.findall(assignment_pattern, code)
        
        for var, value in matches:
            variables.add(var)
            assignments.append((var, value.strip()))
    
    # Create nodes for variables
    for var in list(variables)[:8]:  # Limit to 8 variables
        dot.node(var, var, shape='ellipse', fillcolor='lightblue', style='filled')
    
    # Create assignment operations
    for i, (var, value) in enumerate(assignments[:6]):  # Limit to 6 assignments
        op_id = f'assign_{i}'
        value_label = value[:15] + "..." if len(value) > 15 else value
        dot.node(op_id, f"= {value_label}", shape='box', fillcolor='lightyellow', style='filled')
        dot.edge(op_id, var, label="assigns")
    
    if not variables:
        dot.node('no_data_flow', 'No significant data flow detected', shape='note', fillcolor='lightyellow', style='filled')
    
    return dot.source


def main():
    # Create a professional header with logo styling that works in both dark and light modes
    st.markdown("""
    <style>
        :root {
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --text-color: #2c3e50;
            --bg-light: #ffffff;
            --bg-dark: #1e1e1e;
            --border-light: #e1e8ed;
            --border-dark: #333333;
            --shadow-light: rgba(0, 0, 0, 0.1);
            --shadow-dark: rgba(255, 255, 255, 0.1);
        }
        
        /* Streamlit Dark Mode Detection */
        .stApp[data-theme="dark"] {
            --text-color: #ffffff;
            --bg-card: #262730;
            --border-color: #404040;
            --shadow-color: rgba(255, 255, 255, 0.1);
        }
        
        .stApp[data-theme="light"] {
            --text-color: #2c3e50;
            --bg-card: #ffffff;
            --border-color: #e1e8ed;
            --shadow-color: rgba(0, 0, 0, 0.1);
        }
        
        /* Fallback for systems without explicit theme detection */
        .stApp {
            --text-color: #2c3e50;
            --bg-card: #ffffff;
            --border-color: #e1e8ed;
            --shadow-color: rgba(0, 0, 0, 0.1);
        }
        
        @media (prefers-color-scheme: dark) {
            .stApp:not([data-theme="light"]) {
                --text-color: #ffffff;
                --bg-card: #262730;
                --border-color: #404040;
                --shadow-color: rgba(255, 255, 255, 0.1);
            }
        }
        
        .logo-banner {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            padding: 1.5rem;
            border-radius: 12px;
            color: white;
            text-align: center;
            margin-bottom: 1.5rem;
            box-shadow: 0 4px 20px var(--shadow-color);
        }
        
        .logo-title {
            font-size: 2.2rem;
            font-weight: 700;
            margin: 0;
            letter-spacing: 1px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .logo-subtitle {
            font-size: 1rem;
            opacity: 0.95;
            margin-top: 0.3rem;
            font-weight: 300;
        }
        
        .metric-card {
            background: var(--bg-card);
            padding: 1.2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px var(--shadow-color);
            border: 1px solid var(--border-color);
            text-align: center;
            margin-bottom: 1rem;
            transition: transform 0.2s ease;
            color: var(--text-color);
        }
        
        .metric-card:hover {
            transform: translateY(-2px);
        }
        
        .section-header {
            background: var(--bg-card);
            padding: 0.8rem 1.2rem;
            border-radius: 8px;
            border-left: 4px solid var(--primary-color);
            margin: 1rem 0;
            box-shadow: 0 2px 8px var(--shadow-color);
            color: var(--text-color);
        }
        
        .section-title {
            color: var(--text-color);
            font-size: 1.2rem;
            font-weight: 600;
            margin: 0;
        }
        
        .info-card {
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 8px;
            border-left: 3px solid #17a2b8;
            margin: 0.8rem 0;
            box-shadow: 0 2px 6px var(--shadow-color);
            color: var(--text-color);
        }
        
        .success-card {
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 8px;
            border-left: 3px solid #28a745;
            margin: 0.8rem 0;
            box-shadow: 0 2px 6px var(--shadow-color);
            color: var(--text-color);
        }
        
        .warning-card {
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 8px;
            border-left: 3px solid #ffc107;
            margin: 0.8rem 0;
            box-shadow: 0 2px 6px var(--shadow-color);
            color: var(--text-color);
        }
        
        .error-card {
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 8px;
            border-left: 3px solid #dc3545;
            margin: 0.8rem 0;
            box-shadow: 0 2px 6px var(--shadow-color);
            color: var(--text-color);
        }
        
        .tab-content {
            padding: 1.2rem;
            background: var(--bg-card);
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--shadow-color);
            border: 1px solid var(--border-color);
            color: var(--text-color);
        }
        
        /* Streamlit component styling overrides */
        .stSelectbox > div > div > div {
            background-color: var(--bg-card) !important;
            color: var(--text-color) !important;
            border-color: var(--border-color) !important;
        }
        
        .stTextArea > div > div > textarea {
            background-color: var(--bg-card) !important;
            color: var(--text-color) !important;
            border-color: var(--border-color) !important;
        }
        
        .stFileUploader > div {
            background-color: var(--bg-card) !important;
            border-color: var(--border-color) !important;
        }
        
        /* Button styling for input method selection */
        .input-method-button {
            background: var(--bg-card) !important;
            color: var(--text-color) !important;
            border: 1px solid var(--border-color) !important;
            border-radius: 8px !important;
            padding: 0.5rem 1rem !important;
            margin: 0.2rem !important;
            transition: all 0.2s ease !important;
        }
        
        .input-method-button:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 4px 12px var(--shadow-color) !important;
        }
        
        /* Ensure proper contrast in both modes */
        .stApp[data-theme="dark"] .metric-card h3,
        .stApp[data-theme="dark"] .section-title,
        .stApp[data-theme="dark"] .info-card strong,
        .stApp[data-theme="dark"] .success-card strong,
        .stApp[data-theme="dark"] .warning-card strong,
        .stApp[data-theme="dark"] .error-card strong {
            color: #ffffff !important;
        }
        
        .stApp[data-theme="light"] .metric-card h3,
        .stApp[data-theme="light"] .section-title,
        .stApp[data-theme="light"] .info-card strong,
        .stApp[data-theme="light"] .success-card strong,
        .stApp[data-theme="light"] .warning-card strong,
        .stApp[data-theme="light"] .error-card strong {
            color: #2c3e50 !important;
        }
    </style>

    <div class="logo-banner">
        <h1 class="logo-title">🔍 Codelytics Syntactica</h1>
        <p class="logo-subtitle">Advanced Code Analysis & Quality Engineering Platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Enhanced sidebar with comprehensive information
    with st.sidebar:
        st.markdown('<div class="section-header"><h3 class="section-title">⚙️ Configuration</h3></div>', unsafe_allow_html=True)
        
        # Try to get API key from environment first
        api_key = os.getenv('GEMINI_API_KEY')
        
        if not api_key:
            api_key = st.text_input("🔑 Enter Gemini API Key", type="password", help="Get your API key from Google AI Studio")
        else:
            st.success("✅ API key loaded from .env file")
            # Option to override with manual input
            override_key = st.text_input("🔄 Override API Key (optional)", type="password")
            if override_key:
                api_key = override_key
        
        if not api_key:
            st.warning("⚠️ Please enter your Gemini API key to use AI features")
            st.markdown("[🔗 Get API Key](https://makersuite.google.com/app/apikey)")
            st.info("💡 **Tip**: Create a `.env` file with `GEMINI_API_KEY=your_key_here`")
        
        st.markdown('<div class="section-header"><h3 class="section-title">🎯 About Codelytics Syntactica</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        **Codelytics Syntactica** is a comprehensive, enterprise-grade code analysis platform designed for software engineers, technical leads, and development teams. Our advanced analytical engine combines traditional static analysis with cutting-edge AI to provide deep insights into code quality, security, performance, and maintainability.
        
        Built with industry best practices and powered by Google's Gemini AI, this platform serves as your intelligent code review assistant, helping teams identify potential issues before they reach production.
        """)
        
        st.markdown('<div class="section-header"><h3 class="section-title">🚀 Getting Started Guide</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 📋 Step-by-Step Instructions
        
        **1. API Configuration** 🔑
        - Obtain a Gemini API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
        - Create a `.env` file with `GEMINI_API_KEY=your_api_key`
        - Or enter your API key in the sidebar input field
        
        **2. Code Input Methods** 📁
        - **File Upload**: Upload a code file for analysis (12+ programming languages supported)
        - **Direct Paste**: Copy-paste your code and select the language
        
        **3. View Results** ⚡
        - Real-time metrics and complexity scores are displayed automatically
        - Explore AI-generated insights, recommendations, and visualizations
        
        **4. Export & Share** 📊
        - Download visualization diagrams as DOT files
        - Save analysis results for team collaboration
        """)
        
        st.markdown('<div class="section-header"><h3 class="section-title">🔬 Core Analysis Features</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 📈 Cyclomatic Complexity Analysis
        **What it measures:** Code's structural complexity based on decision points  
        **Formula:** `CC = E - N + 2P` (Edges - Nodes + 2×Connected Components)  
        **Applications:**
        - Risk assessment for bug probability
        - Test case planning and coverage estimation
        - Refactoring priority identification
        - Code review automation
        
        ### 🔒 Advanced Security Scanning
        **OWASP Top 10 Vulnerability Detection:**
        - **SQL Injection**: Pattern matching for unsafe query construction
        - **Command Injection**: Detection of unsafe system calls
        - **XSS Vulnerabilities**: Client-side injection patterns
        - **Insecure Deserialization**: Unsafe object reconstruction
        - **Hardcoded Credentials**: API keys, passwords, tokens exposure
        - **Path Traversal**: Directory traversal attack vectors
        
        ### 🏆 Code Quality Assessment
        **Industry-Standard Metrics:**
        - **Code Smells**: Long methods, parameter overloading, magic numbers
        - **Design Patterns**: Recognition of common architectural patterns
        - **Documentation Coverage**: Comment density and quality analysis
        
        **Best Practices Validation:**
        - Naming conventions adherence
        - Error handling completeness
        - Resource management patterns
        - SOLID principles compliance
        
        ### ⚡ Performance Analysis Engine
        **Algorithmic Complexity Assessment:**
        - **Time Complexity**: Big O notation estimation
        - **Space Complexity**: Memory usage analysis
        - **Loop Analysis**: Nested iterations and optimization opportunities
        - **Recursion Detection**: Stack overflow risk assessment
        
        **Performance Bottleneck Identification:**
        - Inefficient algorithms detection
        - Database query optimization suggestions
        - Memory leak pattern recognition
        - Concurrent programming anti-patterns
        """)
        
        st.markdown('<div class="section-header"><h3 class="section-title">🎨 Advanced Visualization Suite</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 📊 Professional Diagram Generation
        
        **🔄 Control Flow Diagrams**
        - **Purpose**: Visualize program execution paths
        - **Use Cases**: Code review, debugging, documentation
        - **Features**: Decision points, loop structures, exception handling
        
        **🏗️ Class Hierarchy Visualization**
        - **Purpose**: Object-oriented design analysis
        - **Use Cases**: Architecture review, inheritance optimization
        - **Features**: UML-compliant notation, interface detection
        
        **📞 Function Call Graphs**
        - **Purpose**: Dependency mapping and coupling analysis
        - **Use Cases**: Refactoring planning, impact analysis
        - **Features**: Circular dependency detection, modularity scoring
        
        **🔀 Control Flow Graphs (CFG)**
        - **Purpose**: Detailed execution path analysis
        - **Use Cases**: Test coverage planning, dead code detection
        - **Features**: Basic block identification, reachability analysis
        
        **📦 Package Dependency Mapping**
        - **Purpose**: Module relationship visualization
        - **Use Cases**: Architecture governance, dependency management
        - **Features**: Third-party library tracking, version conflict detection
        
        **💾 Data Flow Diagrams**
        - **Purpose**: Variable lifecycle and state management
        - **Use Cases**: Security analysis, optimization opportunities
        - **Features**: Variable scope tracking, mutation detection
        
        ### 🤖 AI-Enhanced Generation
        - Context-aware diagram optimization
        - Intelligent layout algorithms
        - Automated annotation and labeling
        - Interactive exploration capabilities
        """)
        
        st.markdown('<div class="section-header"><h3 class="section-title">🔧 Language Support Matrix</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### **Tier 1: Full AST Analysis** 🌟
        
        **🐍 Python**
        - Abstract Syntax Tree parsing
        - Full complexity analysis including decorators, comprehensions
        - Security pattern detection for Django, Flask frameworks
        - Performance analysis for NumPy, Pandas operations
        
        **☕ Java**
        - Complete syntax tree analysis using JavaLang
        - Enterprise patterns detection (Spring, Hibernate)
        - Memory leak pattern identification
        - Concurrency analysis (Thread safety, synchronization)
        
        **📜 JavaScript/TypeScript**
        - ES6+ feature support
        - Async/await pattern analysis
        - Prototype chain complexity
        - Node.js security patterns
        
        **⚛️ React (JSX/TSX)**
        - Component lifecycle analysis
        - Hook dependency tracking
        - Virtual DOM optimization patterns
        - State management complexity assessment
        
        ### **Tier 2: Advanced Pattern Matching** ⭐
        - **C/C++**: Memory management, pointer analysis
        - **C#**: .NET framework patterns, LINQ complexity
        - **PHP**: Web security patterns, framework analysis
        - **Ruby**: Metaprogramming detection, Rails patterns
        - **Go**: Goroutine analysis, interface complexity
        
        ### **Analysis Methodology:**
        - **Hybrid Approach**: AST + Pattern matching for maximum accuracy
        - **Context Sensitivity**: Framework-aware analysis
        - **Custom Rules**: Extensible rule engine for team standards
        """)
        
        st.markdown('<div class="section-header"><h3 class="section-title">📊 Professional Metrics & Scoring</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 🎯 Complexity Scale
        
        <style>
        .sidebar-table {
            font-size: 0.85rem;
            border-collapse: collapse;
            width: 100%;
        }
        .sidebar-table th, .sidebar-table td {
            border: 1px solid #ddd;
            padding: 0.5rem;
            text-align: left;
            background-color: transparent; /* Ensure no background color */
        }
        .sidebar-table th {
            font-weight: bold;
        }
        </style>
        
        <table class="sidebar-table">
            <thead>
            <tr>
            <th>Range</th>
            <th>Grade</th>
            <th>Risk</th>
            <th>Action</th>
            </tr>
            </thead>
            <tbody>
            <tr>
            <td>1-10</td>
            <td>🟢 A+ Excellent</td>
            <td>Minimal</td>
            <td>Maintain standards</td>
            </tr>
            <tr>
            <td>11-20</td>
            <td>🟡 B+ Good</td>
            <td>Low-Medium</td>
            <td>Minor refactoring</td>
            </tr>
            <tr>
            <td>21-50</td>
            <td>🟠 C+ Fair</td>
            <td>Medium-High</td>
            <td>Refactoring needed</td>
            </tr>
            <tr>
            <td>51+</td>
            <td>🔴 D+ Poor</td>
            <td>Very High</td>
            <td>Immediate action</td>
            </tr>
            </tbody>
        </table>
        """, unsafe_allow_html=True)
        st.markdown("""
        <div class="info-card">
            <h4>💡 Usage Tips</h4>
            <ul>
                <li><strong>Start Small:</strong> Analyze functions individually</li>
                <li><strong>Use AI:</strong> Enable AI for detailed insights</li>
                <li><strong>Visualize:</strong> Generate flowcharts for clarity</li>
                <li><strong>Iterate:</strong> Apply suggestions and re-analyze</li>
                <li><strong>Document:</strong> Save results for team review</li>
            </ul>
        </div>

        <div class="success-card">
            <h4>⚡ Performance</h4>
            <ul>
                <li>Files up to 5000 chars for execution</li>
                <li>AI analysis cached for efficiency</li>
                <li>Visualization optimized for readability</li>
            </ul>
        </div>

        <div class="warning-card">
            <h4>🔒 Security</h4>
            <ul>
                <li>Local execution in sandbox</li>
                <li>No code stored permanently</li>
                <li>API key encryption in transit</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('<div class="section-header"><h3 class="section-title">⚠️ Disclaimer</h3></div>', unsafe_allow_html=True)
        
        st.markdown("""
        ### 🔒 Privacy & Security
        - **No Data Stored:** Your code is processed locally or via secure API calls. No data is stored permanently on our servers.
        - **Secure Execution:** All code execution is sandboxed to prevent unauthorized access or security risks.
        - **API Key Protection:** Your API key is encrypted during transmission and not stored.

        ### 🛠️ Report Issues or Bugs
        - Found a bug or issue? Help us improve by reporting it on our [GitHub Issues Page](https://github.com/pruthakjani5/codelytics_syntactica/issues).
        - For urgent issues, contact us via email or LinkedIn.

        ### 📧 Help & Support
        - Need assistance? Reach out to us at LinkedIn/ GitHub.
        - Check our [documentation](https://github.com/pruthakjani5/codelytics_syntactica/) for detailed guides and FAQs.
        """)
        
    # Professional input section with fixed state management
    st.markdown('<div class="section-header"><h2 class="section-title">📁 Code Input</h2></div>', unsafe_allow_html=True)
    
    # Initialize session state for input method if not exists
    if 'input_method' not in st.session_state:
        st.session_state.input_method = "upload"
    
    # Input method selection with better styling
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📁 Upload File", use_container_width=True, type="primary" if st.session_state.input_method == "upload" else "secondary"):
            st.session_state.input_method = "upload"
    with col2:
        if st.button("✏️ Paste Code", use_container_width=True, type="primary" if st.session_state.input_method == "paste" else "secondary"):
            st.session_state.input_method = "paste"
    
    content = None
    filename = None
    language = None
    
    if st.session_state.input_method == "upload":
        uploaded_file = st.file_uploader(
            "Choose your code file",
            type=['py', 'java', 'js', 'ts', 'jsx', 'tsx', 'cpp', 'c', 'cs', 'php', 'rb', 'go', 'txt'],
            help="📄 Supported: Python, Java, JavaScript, TypeScript, React JSX/TSX, C++, C, C#, PHP, Ruby, Go"
        )
        
        if uploaded_file is not None:
            content = uploaded_file.read().decode('utf-8')
            filename = uploaded_file.name
    
    else:  # Paste Code
        col1, col2 = st.columns([2, 1])
        with col1:
            content = st.text_area(
                "📝 Paste your code here:",
                height=300,
                placeholder="Enter your code to analyze...",
                help="Paste your code for instant analysis",
                key="code_input"
            )
        with col2:
            language_options = ['python', 'java', 'javascript', 'typescript', 'jsx', 'tsx', 'cpp', 'c', 'csharp', 'php', 'ruby', 'go']
            selected_language = st.selectbox("🔤 Select Language:", language_options, key="language_select")
            language = selected_language.lower()
        
            if content:
                # Map language to appropriate file extension
                extension_map = {
                    'python': 'py', 'java': 'java', 'javascript': 'js',
                    'typescript': 'ts', 'jsx': 'jsx', 'tsx': 'tsx', 
                    'cpp': 'cpp', 'c': 'c', 'csharp': 'cs', 
                    'php': 'php', 'ruby': 'rb', 'go': 'go'
                }
                filename = f"code.{extension_map.get(language, 'txt')}"
    
    # Run analysis if we have content from either upload or paste
    if content and content.strip():
            # Initialize analyzer and perform analysis
            analyzer = CodeAnalyzer(api_key)
            if not language:
                language = analyzer.detect_language(filename or "unknown.txt", content)
            
            # Perform complexity analysis
            complexity, details = analyzer.complexity_analyzer.calculate_complexity(content, language)
            bug_probability, risk_icon = analyzer.calculate_bug_probability(complexity)
            
            # Initialize other analyzers
            quality_analyzer = CodeQualityAnalyzer()
            security_scanner = SecurityScanner()
            
            # Main analysis results display
            st.markdown('<div class="section-header"><h2 class="section-title">📊 Analysis Results</h2></div>', unsafe_allow_html=True)
            
            # Create metrics columns
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown(f'''
                <div class="metric-card">
                    <h3 style="margin:0; color:#dc3545;">{complexity}</h3>
                    <p style="margin:0; color:#666;">Cyclomatic Complexity</p>
                </div>
                ''', unsafe_allow_html=True)
            
            with col2:
                st.markdown(f'''
                <div class="metric-card">
                    <h3 style="margin:0; color:#fd7e14;">{risk_icon} {bug_probability}</h3>
                    <p style="margin:0; color:#666;">Bug Risk</p>
                </div>
                ''', unsafe_allow_html=True)
            
            with col3:
                st.markdown(f'''
                <div class="metric-card">
                    <h3 style="margin:0; color:#17a2b8;">{language.title()}</h3>
                    <p style="margin:0; color:#666;">Language</p>
                </div>
                ''', unsafe_allow_html=True)
            
            with col4:
                loc = len([line for line in content.split('\n') if line.strip()])
                st.markdown(f'''
                <div class="metric-card">
                    <h3 style="margin:0; color:#28a745;">{loc}</h3>
                    <p style="margin:0; color:#666;">Lines of Code</p>
                </div>
                ''', unsafe_allow_html=True)
            
            # Complexity breakdown
            if details:
                st.markdown('<div class="section-header"><h3 class="section-title">🔍 Complexity Breakdown</h3></div>', unsafe_allow_html=True)
                breakdown_cols = st.columns(min(len(details), 4))
                
                for i, (construct, count) in enumerate(details.items()):
                    with breakdown_cols[i % 4]:
                        st.markdown(f'''
                        <div class="metric-card">
                            <strong>{construct}</strong><br>
                            <span style="font-size:1.5rem; color:#0066cc;">{count}</span> occurrences
                        </div>
                        ''', unsafe_allow_html=True)
            
            # QUALITY AND SECURITY ANALYSIS
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown('<div class="section-header"><h3 class="section-title">🏆 Code Quality</h3></div>', unsafe_allow_html=True)
                quality_results = quality_analyzer.analyze(content, language)
                
                # Code smells
                code_smells = quality_results.get('code_smells', {})
                if any(count > 0 for count in code_smells.values()):
                    for smell, count in code_smells.items():
                        if count > 0:
                            st.markdown(f'''
                            <div class="warning-card">
                                <strong>⚠️ {smell.replace('_', ' ').title()}</strong><br>
                                {count} instances detected
                            </div>
                            ''', unsafe_allow_html=True)
                else:
                    st.markdown('''
                    <div class="success-card">
                        <strong>✅ No Major Code Smells Detected!</strong><br>
                        Your code follows good practices
                    </div>
                    ''', unsafe_allow_html=True)
                
                # Good practices
                good_practices = quality_results.get('good_practices', {})
                if any(count > 0 for count in good_practices.values()):
                    for practice, count in good_practices.items():
                        if count > 0:
                            st.markdown(f'''
                            <div class="success-card">
                                <strong>✅ {practice.replace('_', ' ').title()}</strong><br>
                                {count} instances found
                            </div>
                            ''', unsafe_allow_html=True)
            
            with col2:
                st.markdown('<div class="section-header"><h3 class="section-title">🔒 Security Analysis</h3></div>', unsafe_allow_html=True)
                security_results = security_scanner.scan(content, language)
                
                if "message" in security_results:
                    st.markdown(f'''
                    <div class="info-card">
                        <strong>ℹ️ Information</strong><br>
                        {security_results["message"]}
                    </div>
                    ''', unsafe_allow_html=True)
                elif security_results:
                    for vuln_type, issues in security_results.items():
                        st.markdown(f'''
                        <div class="error-card">
                            <strong>🚨 {vuln_type.replace('_', ' ').title()}</strong><br>
                            Security vulnerability detected
                        </div>
                        ''', unsafe_allow_html=True)
                else:
                    st.markdown('''
                    <div class="success-card">
                        <strong>✅ No Security Issues Detected!</strong><br>
                        No obvious vulnerabilities found
                    </div>
                    ''', unsafe_allow_html=True)
            
            # PERFORMANCE ANALYSIS
            st.markdown('<div class="section-header"><h2 class="section-title">⚡ Performance Analysis</h2></div>', unsafe_allow_html=True)
            performance_results = estimate_performance(analyzer, content, language)
            
            if "message" in performance_results or "error" in performance_results:
                st.info(performance_results.get("message", performance_results.get("error", "Unknown error")))
            else:
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    big_o = performance_results.get("estimated_big_o", "Unknown")
                    st.markdown(f'''
                    <div class="metric-card">
                        <h3 style="margin:0; color:#dc3545;">{big_o}</h3>
                        <p style="margin:0; color:#666;">Time Complexity</p>
                    </div>
                    ''', unsafe_allow_html=True)
                
                with col2:
                    efficiency = performance_results.get("efficiency_rating", "Unknown")
                    efficiency_colors = {
                        "Excellent": "#28a745", "Good": "#ffc107", "Moderate": "#fd7e14",
                        "Low": "#dc3545", "Potentially problematic": "#dc3545"
                    }
                    color = efficiency_colors.get(efficiency, "#6c757d")
                    st.markdown(f'''
                    <div class="metric-card">
                        <h3 style="margin:0; color:{color};">{efficiency}</h3>
                        <p style="margin:0; color:#666;">Efficiency Rating</p>
                    </div>
                    ''', unsafe_allow_html=True)
                
                with col3:
                    loops = performance_results.get("loop_count", 0)
                    st.markdown(f'''
                    <div class="metric-card">
                        <h3 style="margin:0; color:#17a2b8;">{loops}</h3>
                        <p style="margin:0; color:#666;">Loops Detected</p>
                    </div>
                    ''', unsafe_allow_html=True)
                
                # Performance warnings
                if performance_results.get("nested_loops", 0) > 0:
                    st.warning(f"⚠️ {performance_results['nested_loops']} nested loops detected - may impact performance")
                
                if performance_results.get("recursion_detected", False):
                    st.warning("⚠️ Recursion detected - monitor for potential stack overflow")
            
            # CODE EXECUTION VISUALIZATION (Python only)
            if language == 'python':
                st.markdown('<div class="section-header"><h2 class="section-title">🔍 Code Execution Trace</h2></div>', unsafe_allow_html=True)
                
                if st.button("▶️ Run Code Execution Trace", type="primary", use_container_width=True):
                    with st.spinner("⚙️ Tracing code execution..."):
                        viz_results = visualize_code_execution(content, language)
                    
                    if "message" in viz_results:
                        st.info(viz_results["message"])
                    elif "error" in viz_results:
                        st.error(f"❌ Error: {viz_results['error']}")
                    else:
                        st.success("✅ Code execution traced successfully!")
                        
                        # Display execution steps with better styling
                        if "steps" in viz_results and viz_results["steps"]:
                            st.markdown("### 📝 Execution Steps")
                            for i, step in enumerate(viz_results["steps"], 1):
                                step_type = step.get("type", "unknown")
                                content_str = step.get("content", "")
                                
                                if step_type == "output":
                                    st.code(f"Output: {content_str}", language='text')
                                elif step_type == "error":
                                    st.error(f"Error: {content_str}")
                                elif step_type == "section":
                                    st.markdown(f"### {content_str}")
                                else:
                                    st.info(f"Step {i}: {content_str}")
                        
                        # Show raw output in expander
                        with st.expander("🔍 Raw Execution Output"):
                            st.code(viz_results.get("raw_output", "No output"), language='text')
            
            # ADVANCED CODE VISUALIZATIONS SECTION
            st.markdown('<div class="section-header"><h2 class="section-title">📊 Advanced Code Visualizations</h2></div>', unsafe_allow_html=True)
            
            # Cache flowchart generation
            @st.cache_data(show_spinner="🎨 Generating visualization...")
            def generate_cached_visualization(code_content, lang, viz_type, use_ai, api_key_hash):
                """Cache visualization generation"""
                if viz_type == "Flowchart (Basic)":
                    if use_ai and api_key:
                        temp_analyzer = CodeAnalyzer(api_key)
                        return temp_analyzer.generate_flowchart_with_ai(code_content, lang)
                    else:
                        temp_analyzer = CodeAnalyzer("")
                        return temp_analyzer._generate_fallback_flowchart(code_content, lang)
                elif viz_type == "Class Hierarchy":
                    return generate_class_hierarchy(code_content, lang)
                elif viz_type == "Function Call Graph":
                    return generate_call_graph(code_content, lang)
                elif viz_type == "Control Flow Graph":
                    return generate_control_flow_graph(code_content, lang)
                elif viz_type == "Package Dependencies":
                    return generate_package_dependency_graph(code_content, lang)
                elif viz_type == "Data Flow":
                    return generate_data_flow_diagram(code_content, lang)

            # Visualization controls with better styling
            col1, col2 = st.columns([3, 1])
            with col1:
                visualization_type = st.selectbox(
                    "🎯 Select visualization type:",
                    [
                        "Flowchart (Basic)", 
                        "Class Hierarchy", 
                        "Function Call Graph",
                        "Control Flow Graph",
                        "Package Dependencies",
                        "Data Flow"
                    ],
                    help="Choose the type of diagram to generate for your code"
                )
            with col2:
                use_ai_flowchart = st.checkbox(
                    "🤖 Use AI-Enhanced", 
                    value=bool(api_key), 
                    disabled=not api_key or visualization_type != "Flowchart (Basic)",
                    help="Use AI for smarter diagram generation (API key required)"
                )

            # Generate visualization using cached function
            api_key_hash = hash(api_key) if api_key else 0
            
            with st.spinner(f"🎨 Generating {visualization_type}..."):
                flowchart_source = generate_cached_visualization(
                    content, language, visualization_type, use_ai_flowchart, api_key_hash
                )

            # Display the visualization with enhanced error handling
            try:
                st.graphviz_chart(flowchart_source, use_container_width=True)
                
                # Success message and additional options
                st.success(f"✅ {visualization_type} generated successfully!")
                
                # Option to download visualization
                with st.expander("📄 View & Download Diagram Source Code"):
                    st.markdown("**DOT Language Source Code:**")
                    st.code(flowchart_source, language='dot')
                    
                    # Download button with dynamic filename
                    safe_filename = filename.replace('.', '_') if filename else "code"
                    viz_filename = f"{safe_filename}_{visualization_type.lower().replace(' ', '_').replace('(', '').replace(')', '')}.dot"
                    
                    st.download_button(
                        label=f"📥 Download {visualization_type} DOT file",
                        data=flowchart_source,
                        file_name=viz_filename,
                        mime="text/plain",
                        help="Download the diagram source code for external use"
                    )
                    
                    # Additional export information
                    st.markdown("""
                    **💡 Export Options:**
                    - Use the DOT file with Graphviz tools
                    - Convert to PNG/SVG: `dot -Tpng input.dot -o output.png`
                    - Online editors: [GraphvizOnline](https://dreampuf.github.io/GraphvizOnline/)
                    """)
                    
            except Exception as chart_error:
                st.error(f"❌ Error rendering diagram: {str(chart_error)}")
                
                # Fallback display
                st.markdown('''
                <div class="warning-card">
                    <h4>⚠️ Visualization Error</h4>
                    <p>Unable to render the diagram. Showing source code instead:</p>
                </div>
                ''', unsafe_allow_html=True)
                
                st.code(flowchart_source, language='dot')
                
                # Installation help
                st.markdown('''
                <div class="info-card">
                    <h4>🔧 Installation Required</h4>
                    <p>To fix visualization rendering, install Graphviz:</p>
                </div>
                ''', unsafe_allow_html=True)
                
                st.markdown("""
                **Install Graphviz System Package:**
                - **Windows**: Download from [graphviz.org](https://graphviz.org/download/) and add to PATH
                - **macOS**: `brew install graphviz`
                - **Ubuntu/Debian**: `sudo apt-get install graphviz`
                - **CentOS/RHEL**: `sudo yum install graphviz`
                
                **Python Package:**
                ```bash
                pip install graphviz
                ```
                
                **For Streamlit Cloud/Hosting:**
                Add `graphviz` to your `packages.txt` file for system dependencies.
                """)

            # AI ANALYSIS SECTION
            if api_key:
                st.markdown('<div class="section-header"><h2 class="section-title">🤖 AI-Powered Analysis</h2></div>', unsafe_allow_html=True)
                
                # Cache AI analysis to prevent repeated calls
                @st.cache_data(show_spinner="🧠 Analyzing code with Gemini AI...")
                def get_ai_analysis(code_content, lang, api_key_hash):
                    """Cache AI analysis results based on code content and language"""
                    temp_analyzer = CodeAnalyzer(api_key)
                    return temp_analyzer.analyze_with_gemini(code_content, lang)
                
                # Create a hash of the API key for caching
                api_key_hash = hash(api_key) if api_key else 0
                ai_results = get_ai_analysis(content, language, api_key_hash)
                
                # Create tabs for different analyses with better styling
                tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                    "📝 Summary", "📋 Pseudocode", "⏱️ Time", 
                    "💾 Space", "🔄 Flow", "🔧 Refactor"
                ])
                
                with tab1:
                    # st.markdown('<div class="tab-content">', unsafe_allow_html=True)
                    st.markdown("### 📊 Code Summary")
                    st.write(ai_results.get('summary', 'No summary available'))
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with tab2:
                    # st.markdown('<div class="tab-content">', unsafe_allow_html=True)
                    st.markdown("### 📋 Pseudocode")
                    pseudocode = ai_results.get('pseudocode', 'No pseudocode available')
                    st.markdown(pseudocode)
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with tab3:
                    # st.markdown('<div class="tab-content">', unsafe_allow_html=True)
                    st.markdown("### ⏱️ Time Complexity Analysis")
                    st.write(ai_results.get('time_complexity', 'No time complexity analysis available'))
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with tab4:
                    # st.markdown('<div class="tab-content">', unsafe_allow_html=True)
                    st.markdown("### 💾 Space Complexity Analysis")
                    st.write(ai_results.get('space_complexity', 'No space complexity analysis available'))
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with tab5:
                    # st.markdown('<div class="tab-content">', unsafe_allow_html=True)
                    st.markdown("### 🔄 Execution Flow")
                    st.write(ai_results.get('execution_flow', 'No execution flow analysis available'))
                    st.markdown('</div>', unsafe_allow_html=True)
                
                with tab6:
                    st.markdown('<div class="tab-content">', unsafe_allow_html=True)
                    st.markdown("### 🔧 Refactoring Suggestions")
                    
                    # Cache refactoring suggestions
                    @st.cache_data(show_spinner="💡 Generating refactoring suggestions...")
                    def get_refactoring_suggestions(code_content, lang, complexity_val, details_dict, api_key_hash):
                        """Cache refactoring suggestions"""
                        temp_analyzer = CodeAnalyzer(api_key)
                        return generate_refactoring_suggestions(temp_analyzer, code_content, lang, complexity_val, details_dict)
                    
                    refactoring_results = get_refactoring_suggestions(content, language, complexity, details, api_key_hash)
                    
                    if "message" in refactoring_results:
                        st.info(refactoring_results["message"])
                    elif "error" in refactoring_results:
                        st.error(refactoring_results["error"])
                    elif "suggestions" in refactoring_results:
                        st.markdown(refactoring_results["suggestions"])
                    else:
                        st.info("No refactoring suggestions available")
                    st.markdown('</div>', unsafe_allow_html=True)

            # RECOMMENDATIONS SECTION
            st.markdown('<div class="section-header"><h2 class="section-title">💡 Professional Recommendations</h2></div>', unsafe_allow_html=True)
            
            if complexity <= 10:
                st.markdown('''
                <div class="success-card">
                    <h4>✅ Excellent Code Quality!</h4>
                    <p>Your code demonstrates exceptional structure and maintainability. Continue following clean code principles and consider adding comprehensive unit tests to maintain this quality standard.</p>
                </div>
                ''', unsafe_allow_html=True)
            elif complexity <= 20:
                st.markdown('''
                <div class="warning-card">
                    <h4>⚠️ Moderate Complexity Detected</h4>
                    <p><strong>Action Required:</strong> Consider refactoring for improved maintainability.</p>
                    <ul>
                        <li>Break down large functions into smaller, focused functions</li>
                        <li>Use early returns to reduce nesting levels</li>
                        <li>Extract repeated code patterns into reusable functions</li>
                        <li>Consider applying the Single Responsibility Principle</li>
                    </ul>
                </div>
                ''', unsafe_allow_html=True)
            else:
                st.markdown('''
                <div class="error-card">
                    <h4>🚨 Critical Complexity Alert!</h4>
                    <p><strong>Immediate Action Required:</strong> This code requires urgent refactoring to prevent maintenance issues.</p>
                    <ul>
                        <li><strong>Priority 1:</strong> Break large functions into smaller ones (max 20 lines each)</li>
                        <li><strong>Priority 2:</strong> Reduce nesting with guard clauses and early returns</li>
                        <li><strong>Priority 3:</strong> Extract methods for complex logic blocks</li>
                        <li><strong>Priority 4:</strong> Consider design patterns (Strategy, State, Command)</li>
                        <li><strong>Priority 5:</strong> Add comprehensive tests before refactoring</li>
                    </ul>
                </div>
                ''', unsafe_allow_html=True)
                
                if complexity > 50:
                    st.markdown('''
                    <div class="error-card" style="border-left-color: #721c24;">
                        <h4>⚠️ CRITICAL ALERT: Extremely High Complexity</h4>
                        <p>This code is at critical risk of being unmaintainable. Consider a complete architectural review.</p>
                    </div>
                    ''', unsafe_allow_html=True)
        
    # Enhanced Professional Footer
    st.markdown("---")
    st.markdown("""
    <style>
    .footer-section {
        margin-top: 3rem;
        padding: 2rem;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 15px;
        border: 1px solid #dee2e6;
        text-align: center;
    }
    .author-name {
        font-size: 1.3rem;
        font-weight: 700;
        color: #2c3e50;
        margin-bottom: 0.5rem;
    }
    .version-info {
        font-size: 1rem;
        color: #6c757d;
        margin-bottom: 1rem;
        font-weight: 500;
    }
    .contact-links a {
        margin: 0 1rem;
        transition: transform 0.2s ease;
    }
    .contact-links a:hover {
        transform: translateY(-2px);
    }
    .contact-links img {
        height: 35px;
        width: auto;
        border-radius: 5px;
    }
    .features-list {
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 1rem;
        margin: 1rem 0;
        font-size: 0.9rem;
        color: #495057;
    }
    .feature-item {
        background: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        border: 1px solid #dee2e6;
    }
    </style>
    <div class="footer-section">
        <div class="author-name">🚀 Developed by Pruthak Jani</div>
        <div class="version-info">Codelytics Syntactica v1.0 | Advanced Code Analysis Platform</div>
        <div class="features-list">
            <span class="feature-item">📊 Complexity Analysis</span>
            <span class="feature-item">🔒 Security Scanning</span>
            <span class="feature-item">🤖 AI-Powered Insights</span>
            <span class="feature-item">📈 Performance Metrics</span>
            <span class="feature-item">🎨 Visual Flowcharts</span>
        </div>
        <div class="contact-links">
            <a href="https://github.com/pruthakjani5" target="_blank">
                <img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
            </a>
            <a href="https://www.linkedin.com/in/pruthak-jani/" target="_blank">
                <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
            </a>
        </div>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
