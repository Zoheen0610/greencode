# Green Code Analyzer

A **static code analyzer** to measure energy efficiency of Python code.  
It analyzes loops, nested loops, function calls, and conditionals, then gives an **energy score** with improvement suggestions.

## Installation

```bash
git clone https://github.com/<your-username>/green-code-analyzer.git
cd green-code-analyzer
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
