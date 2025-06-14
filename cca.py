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
    """Scans code for security vulnerabilities"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'python': {
                'sql_injection': r'execute\s*\(\s*[\'"][^\'")]*(\%s|\{[^}]*\}|\$[a-zA-Z0-9_]+)[^\'")]*[\'"]\s*%\s*\(',
                'command_injection': r'os\.system\s*\(|subprocess\.call\s*\(|subprocess\.Popen\s*\(|exec\s*\(',
                'insecure_deserialization': r'pickle\.loads|yaml\.load\s*\([^)]*\)|eval\s*\(',
                'hardcoded_credentials': r'password\s*=\s*[\'"][^\'"]+[\'"]\s*|api_key\s*=\s*[\'"][^\'"]+[\'"]\s*|token\s*=',
                'path_traversal': r'open\s*\(\s*[\'"][^\'")]*(\.\.|~)[^\'")]*[\'"]\s*\)',
            },
            'java': {
                'sql_injection': r'executeQuery\s*\(\s*[\'"][^\'")]*(\+|\%s|\{[^}]*\})[^\'")]*[\'"]\s*\)',
                'command_injection': r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder',
                'xxe': r'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory',
                'insecure_random': r'java\.util\.Random',
                'path_traversal': r'new\s+File\s*\(\s*[\'"][^\'")]*(\.\.|~)[^\'")]*[\'"]\s*\)',
            }
        }
    
    def scan(self, code: str, language: str) -> Dict[str, List[str]]:
        """Scan code for security vulnerabilities"""
        vulnerabilities = {}
        lang_patterns = self.vulnerability_patterns.get(language.lower(), {})
        
        if not lang_patterns:
            return {"message": "Security scanning not available for this language"}
        
        for vuln_name, pattern in lang_patterns.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                vulnerabilities[vuln_name] = [f"Found potential {vuln_name}"]
        
        return vulnerabilities

def generate_refactoring_suggestions(self, code: str, language: str, complexity: int, details: Dict) -> Dict[str, str]:
    """Generate specific refactoring suggestions using Gemini AI"""
    if not self.model:
        return {"message": "API key required for refactoring suggestions"}
    
    try:
        # Identify the biggest complexity contributors
        complexity_contributors = sorted(details.items(), key=lambda x: x[1], reverse=True)
        top_contributors = complexity_contributors[:3]
        
        prompt = f"""
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
        
        response = self.model.generate_content(prompt)
        return {"suggestions": response.text}
    except Exception as e:
        return {"error": f"Failed to generate refactoring suggestions: {str(e)}"}

def estimate_performance(self, code: str, language: str) -> Dict[str, Any]:
    """Estimate code performance characteristics"""
    try:
        if language not in ['python', 'java', 'javascript']:
            return {"message": "Performance estimation not available for this language"}
        
        # Count loops and identify nested loops
        single_loops = len(re.findall(r'\b(for|while)\b', code))
        nested_loops = len(re.findall(r'\b(for|while)\b[^{]*?{[^}]*?\b(for|while)\b', code, re.DOTALL))
        recursion = len(re.findall(r'def\s+(\w+)[^{]*?{[^}]*?\1\s*\(', code, re.DOTALL))
        
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

def visualize_code_execution(code: str, language: str) -> Dict[str, Any]:
    """Create interactive code execution visualization"""
    if language != 'python':
        return {"message": "Code visualization only available for Python"}
    
    try:
        # Create a temporary file to run the code directly with tracing
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
            # Create instrumented code that captures execution without PySnooper dependency
            instrumented_code = f"""
import sys
import traceback
from io import StringIO

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
            temp.write(instrumented_code.encode())
            temp_path = temp.name
        
        # Run the instrumented code
        result = subprocess.run([sys.executable, temp_path], 
                               capture_output=True, text=True, timeout=30)
        
        # Parse the output
        output = result.stdout + result.stderr
        if not output.strip():
            output = "No output generated"
        
        # Clean up
        os.unlink(temp_path)
        
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
    except Exception as visualization_error:
        return {"error": f"Error in code visualization: {str(visualization_error)}"}


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
                You are an expert code analyst.
                Analyze this {language} code and provide a concise summary of what it does and its main functionality:
                
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
                
                Describe how the code executes step by step in a clear, structured manner.
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

def main():
    # Create a professional header with logo styling
    st.markdown("""
    <style>
        .logo-banner {
            background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
            padding: 1.5rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .logo-title {
            font-size: 2.5rem;
            font-weight: 700;
            margin: 0;
            letter-spacing: 1px;
        }
        .logo-subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
            margin-top: 0.5rem;
        }
    </style>

    <div class="logo-banner">
        <h1 class="logo-title">🔍 Codelytics Syntactica: Code Complexity Analyzer</h1>
        <p class="logo-subtitle">Advanced code analysis & quality engineering platform</p>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    # Sidebar for API key
    with st.sidebar:
        st.header("Configuration")
        
        # Try to get API key from environment first
        api_key = os.getenv('GEMINI_API_KEY')
        
        if not api_key:
            api_key = st.text_input("Enter Gemini API Key", type="password", help="Get your API key from Google AI Studio")
        else:
            st.success("✅ API key loaded from .env file")
            # Option to override with manual input
            override_key = st.text_input("Override API Key (optional)", type="password")
            if override_key:
                api_key = override_key
        
        if not api_key:
            st.warning("Please enter your Gemini API key to use AI features")
            st.markdown("[Get API Key](https://makersuite.google.com/app/apikey)")
            st.info("💡 **Tip**: Create a `.env` file with `GEMINI_API_KEY=your_key_here`")
        st.header("📊 Metrics Explained")
        
        st.markdown("""
        ## About Codelytics Syntactica
        
        **Codelytics Syntactica** is a comprehensive code analysis platform that helps you understand and improve your code quality through advanced metrics, visualization, and AI-powered insights.
        
        ### 🔍 Key Features
        - **Complexity Analysis**: Calculates cyclomatic complexity to measure code complexity
        - **Security Scanning**: Identifies potential security vulnerabilities
        - **Performance Analysis**: Estimates algorithmic complexity and efficiency
        - **Code Quality**: Detects code smells and good practices
        - **AI-Powered Insights**: Uses Gemini AI for advanced analysis
        - **Visual Flow**: Generates flowcharts to visualize code execution
        
        ### 📈 Key Metrics Explained
        
        #### **Cyclomatic Complexity**
        - Measures the number of linearly independent paths through code
        - **1-10**: Low complexity (Easy to maintain)
        - **11-20**: Moderate complexity (Some refactoring needed)
        - **21-50**: High complexity (Needs refactoring)
        - **50+**: Very high complexity (Critical refactoring required)
        
        #### **Bug Probability**
        - Estimates likelihood of bugs based on complexity
        - 🟢 **Low**: Well-structured, fewer bugs expected
        - 🟡 **Medium**: Some complexity, moderate bug risk
        - 🟠 **High**: Complex code, higher bug probability
        - 🔴 **Very High**: Critical complexity, high bug risk
        
        #### **Maintainability Index**
        - Measures how easy it is to maintain the code
        - Calculated as: `max(0, 100 - (complexity × 2))`
        - Higher percentages indicate better maintainability
        
        #### **Code Smells**
        - **Long Functions**: Functions with too many lines
        - **Too Many Parameters**: Functions with excessive parameters
        - **Magic Numbers**: Hardcoded numbers without explanation
        
        #### **Security Vulnerabilities**
        - **SQL Injection**: Unsafe database queries
        - **Command Injection**: Unsafe system command execution
        - **Path Traversal**: Unsafe file path handling
        - **Hardcoded Credentials**: Passwords/keys in source code
        
        #### **Performance Metrics**
        - **Big O Notation**: Algorithmic time complexity
        - **Efficiency Rating**: Overall performance assessment
        - **Loop Analysis**: Detection of nested loops and recursion
        
        ### 🤖 AI Features
        
        With a Gemini API key, you get:
        - **Code Summary**: Natural language explanation
        - **Pseudocode**: Simplified algorithm representation
        - **Complexity Analysis**: Detailed time/space complexity
        - **Refactoring Suggestions**: AI-powered improvement tips
        - **Enhanced Flowcharts**: Intelligent visual representations
        
        ### 💡 How to Use
        
        1. **Upload** a code file or **paste** code directly
        2. **Review** the complexity metrics and recommendations
        3. **Analyze** security vulnerabilities and code quality
        4. **Visualize** code flow with interactive flowcharts
        5. **Apply** AI-powered refactoring suggestions
        
        ### 🔧 Supported Languages
        
        - Python (.py)
        - Java (.java)
        - JavaScript (.js)
        - C++ (.cpp)
        - C (.c)
        - C# (.cs)
        - PHP (.php)
        - Ruby (.rb)
        - Go (.go)
        """)
    # Input method selection
    input_method = st.radio(
        "Choose input method:",
        ["📁 Upload File", "✏️ Paste Code"],
        horizontal=True
    )
    
    content = None
    filename = None
    
    if input_method == "📁 Upload File":
        uploaded_file = st.file_uploader(
            "Upload your code file",
            type=['py', 'java', 'js', 'cpp', 'c', 'cs', 'php', 'rb', 'go', 'txt'],
            help="Supported formats: Python, Java, JavaScript, C++, C, C#, PHP, Ruby, Go"
        )
        
        if uploaded_file is not None:
            content = uploaded_file.read().decode('utf-8')
            filename = uploaded_file.name
    
    else:  # Paste Code
        language_options = ['python', 'java', 'javascript', 'cpp', 'c', 'csharp', 'php', 'ruby', 'go']
        selected_language = st.selectbox("Select programming language:", language_options)
        language = selected_language.lower()
        
        content = st.text_area(
            "Paste your code here:",
            height=300,
            placeholder="Paste your code here...",
            help="Enter your code to analyze"
        )
        
        if content:
            filename = f"code.{selected_language}"
    
    if content:
        # Initialize analyzer and additional components
        if api_key:
            analyzer = CodeAnalyzer(api_key)
        else:
            analyzer = CodeAnalyzer("")
        
        quality_analyzer = CodeQualityAnalyzer()
        security_scanner = SecurityScanner()
        
        # Detect language
        if input_method == "📁 Upload File":
            language = analyzer.detect_language(filename, content)
        else:
            # For pasted code, use the selected language
            language = selected_language.lower()

        # Display file info
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("File", filename)
        with col2:
            st.metric("Language", language.title())
        with col3:
            st.metric("Lines of Code", len(content.split('\n')))
        
        # Show code
        with st.expander("📄 View Code", expanded=False):
            st.code(content, language=language)
        
        # Calculate complexity
        st.header("📊 Complexity Analysis")
        
        complexity, details = analyzer.complexity_analyzer.calculate_complexity(content, language)
        bug_prob, bug_icon = analyzer.calculate_bug_probability(complexity)
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Cyclomatic Complexity", complexity)
        with col2:
            st.metric("Bug Probability", f"{bug_icon} {bug_prob}")
        with col3:
            maintainability = max(0, 100 - (complexity * 2))
            st.metric("Maintainability Index", f"{maintainability}%")
        
        # Complexity details
        if details:
            st.subheader("Complexity Breakdown")
            for construct, count in details.items():
                st.write(f"• **{construct}**: {count} occurrences")
        
        # Code Quality Analysis
        st.header("🏆 Code Quality Analysis")
        quality_results = quality_analyzer.analyze(content, language)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Code Smells Detected")
            code_smells = quality_results.get('code_smells', {})
            if any(count > 0 for count in code_smells.values()):
                for smell, count in code_smells.items():
                    if count > 0:
                        st.warning(f"**{smell.replace('_', ' ').title()}**: {count} instances")
            else:
                st.success("✅ No major code smells detected!")
        
        with col2:
            st.subheader("✅ Good Practices Found")
            good_practices = quality_results.get('good_practices', {})
            if any(count > 0 for count in good_practices.values()):
                for practice, count in good_practices.items():
                    if count > 0:
                        st.success(f"**{practice.replace('_', ' ').title()}**: {count} instances")
            else:
                st.info("Consider adding documentation and type hints for better code quality")
        
        # Security Analysis
        st.header("🔒 Security Analysis")
        security_results = security_scanner.scan(content, language)
        
        if "message" in security_results:
            st.info(security_results["message"])
        elif security_results:
            st.error("🚨 **Security vulnerabilities detected!**")
            for vuln_type, issues in security_results.items():
                st.warning(f"**{vuln_type.replace('_', ' ').title()}**")
                for issue in issues:
                    st.write(f"• {issue}")
        else:
            st.success("✅ No obvious security vulnerabilities detected!")
        
        # Performance Estimation
        st.header("⚡ Performance Analysis")
        performance_results = estimate_performance(analyzer, content, language)
        
        if "message" in performance_results:
            st.info(performance_results["message"])
        elif "error" in performance_results:
            st.error(performance_results["error"])
        else:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Estimated Big O", performance_results.get("estimated_big_o", "Unknown"))
            with col2:
                efficiency = performance_results.get("efficiency_rating", "Unknown")
                efficiency_color = {
                    "Excellent": "🟢",
                    "Good": "🟡", 
                    "Moderate": "🟠",
                    "Low": "🔴",
                    "Potentially problematic": "🔴"
                }.get(efficiency, "⚪")
                st.metric("Efficiency", f"{efficiency_color} {efficiency}")
            with col3:
                st.metric("Loops Detected", performance_results.get("loop_count", 0))
            
            if performance_results.get("nested_loops", 0) > 0:
                st.warning(f"⚠️ {performance_results['nested_loops']} nested loops detected - may impact performance")
            
            if performance_results.get("recursion_detected", False):
                st.warning("⚠️ Recursion detected - monitor for potential stack overflow")
        
        # Code Execution Visualization (Python only)
        if language == 'python':
            st.header("🔍 Code Execution Visualization")
            
            if st.button("Generate Execution Trace"):
                with st.spinner("Tracing code execution..."):
                    viz_results = visualize_code_execution(content, language)
                
                if "message" in viz_results:
                    st.info(viz_results["message"])
                elif "error" in viz_results:
                    st.error(f"Error: {viz_results['error']}")
                else:
                    st.success("✅ Code execution traced successfully!")
                    
                    # Display execution steps
                    if "steps" in viz_results and viz_results["steps"]:
                        st.subheader("Execution Steps")
                        for i, step in enumerate(viz_results["steps"], 1):
                            step_type = step.get("type", "unknown")
                            content_str = step.get("content", "")
                            
                            if step_type == "code":
                                st.code(f"Step {i}: {content_str}", language='python')
                            elif step_type == "variable":
                                st.info(f"Step {i}: {content_str}")
                            elif step_type == "return":
                                st.success(f"Step {i}: {content_str}")
                    
                    # Show raw output in expander
                    with st.expander("🔍 Raw Execution Output"):
                        st.code(viz_results.get("raw_output", "No output"), language='text')
        
        # Improved Flowchart Section
        st.header("🔄 Code Flowchart")
        
        # Add flowchart options
        col1, col2 = st.columns([3, 1])
        with col1:
            st.write("Visual representation of your code's execution flow")
        with col2:
            use_ai_flowchart = st.checkbox("Use AI-Enhanced Flowchart", value=bool(api_key), disabled=not api_key)
        
        try:
            if use_ai_flowchart and api_key:
                with st.spinner("🤖 Generating AI-enhanced flowchart..."):
                    flowchart_source = analyzer.generate_flowchart_with_ai(content, language)
                st.success("AI-enhanced flowchart generated!")
            else:
                flowchart_source = analyzer._generate_fallback_flowchart(content, language)
            
            # Display flowchart with better formatting and error handling
            try:
                st.graphviz_chart(flowchart_source, use_container_width=True)
            except Exception as chart_error:
                st.error(f"Error rendering flowchart: {str(chart_error)}")
                st.info("Trying alternative rendering...")
                # Show the DOT source as fallback
                st.code(flowchart_source, language='dot')
            
            # Option to download flowchart
            with st.expander("📄 View Flowchart Source Code"):
                st.code(flowchart_source, language='dot')
                st.download_button(
                    label="Download DOT file",
                    data=flowchart_source,
                    file_name=f"{filename}_flowchart.dot",
                    mime="text/plain"
                )
                
        except Exception as e:
            st.error(f"Could not generate flowchart: {str(e)}")
            st.info("💡 **Installation needed**: `pip install graphviz` and install Graphviz system package")
            st.markdown("""
            **Install Graphviz:**
            - **Windows**: Download from [graphviz.org](https://graphviz.org/download/)
            - **macOS**: `brew install graphviz`
            - **Ubuntu/Debian**: `sudo apt-get install graphviz`
            """)
        
        # AI Analysis (if API key provided)
        if api_key:
            st.header("🤖 AI-Powered Analysis")
            
            with st.spinner("Analyzing code with Gemini AI..."):
                ai_results = analyzer.analyze_with_gemini(content, language)
            
            # Create tabs for different analyses
            tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
                "📝 Summary", "📋 Pseudocode", "⏱️ Time Complexity", 
                "💾 Space Complexity", "🔄 Execution Flow", "🔧 Refactoring"
            ])
            
            with tab1:
                st.markdown("### Code Summary")
                st.write(ai_results.get('summary', 'No summary available'))
            
            with tab2:
                st.markdown("### Pseudocode")
                # Render pseudocode as markdown to preserve formatting
                pseudocode = ai_results.get('pseudocode', 'No pseudocode available')
                st.markdown(pseudocode)
            
            with tab3:
                st.markdown("### Time Complexity Analysis")
                st.write(ai_results.get('time_complexity', 'No time complexity analysis available'))
            
            with tab4:
                st.markdown("### Space Complexity Analysis")
                st.write(ai_results.get('space_complexity', 'No space complexity analysis available'))
            
            with tab5:
                st.markdown("### Execution Flow")
                st.write(ai_results.get('execution_flow', 'No execution flow analysis available'))
            
            with tab6:
                st.markdown("### Refactoring Suggestions")
                refactoring_results = generate_refactoring_suggestions(analyzer, content, language, complexity, details)
                
                if "message" in refactoring_results:
                    st.info(refactoring_results["message"])
                elif "error" in refactoring_results:
                    st.error(refactoring_results["error"])
                elif "suggestions" in refactoring_results:
                    st.markdown(refactoring_results["suggestions"])
                else:
                    st.info("No refactoring suggestions available")
        
        # Enhanced Recommendations
        st.header("💡 Recommendations")
        
        if complexity <= 10:
            st.success("✅ **Excellent complexity!** Your code is well-structured and highly maintainable.")
            st.info("**Best Practices:** Continue following clean code principles and consider adding unit tests.")
        elif complexity <= 20:
            st.warning("⚠️ **Moderate complexity.** Consider some refactoring for better maintainability.")
            st.markdown("""
            **Suggestions:**
            - Break down large functions into smaller, focused functions
            - Consider using early returns to reduce nesting
            - Look for repeated code patterns that can be extracted
            """)
        else:
            st.error("🚨 **High complexity detected!** Immediate refactoring is strongly recommended.")
            st.markdown("""
            **Critical Refactoring Actions:**
            - **Urgent**: Break large functions into smaller ones (max 20 lines per function)
            - **Reduce nesting**: Use early returns and guard clauses
            - **Extract methods**: Look for code blocks that can become separate functions
            - **Design patterns**: Consider Strategy, State, or Command patterns for complex logic
            - **Add tests**: Before refactoring, ensure you have comprehensive tests
            """)
            
            # Add specific suggestions based on complexity level
            if complexity > 50:
                st.error("⚠️ **Critical**: This code has extremely high complexity and may be unmaintainable!")
    # Professional footer
    st.markdown("---")
    st.markdown("""
    <style>
    .footer-section {
        margin-top: 2rem;
        padding: 1rem;
        background-color: #f8f9fa;
        border-radius: 6px;
        border-left: 3px solid #0066cc;
        text-align: center;
    }
    .author-name {
        font-size: 1rem;
        font-weight: 600;
        color: #2c3e50;
        margin-bottom: 0.3rem;
    }
    .version-info {
        font-size: 0.8rem;
        color: #6c757d;
        margin-bottom: 0.5rem;
    }
    .contact-links {
        margin-top: 0.3rem;
    }
    .contact-links a {
        color: #0066cc;
        text-decoration: none;
        margin: 0 0.5rem;
        font-weight: 500;
    }
    .contact-links a:hover {
        text-decoration: underline;
    }
    .contact-links img {
        height: 20px;
        width: auto;
    }
    </style>
    <div class="footer-section">
        <div class="author-name">Developed by Pruthak Jani</div>
        <div class="version-info">Codelytics Syntactica v1.0 | Advanced Code Analysis Platform</div>
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
