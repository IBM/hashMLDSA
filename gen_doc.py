#
# Copyright 2025 IBM
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re

def parse_comment_block(comment):
    func_name = ""
    brief = ""
    desc_lines = []
    params = []
    returns = ""

    lines = comment.strip().split('\n')
    mode = None

    for line in lines:
        line = line.strip().lstrip('*').strip()
        if not line:
            continue
        if re.match(r'^\w+\s+-\s+', line):
            parts = line.split('-', 1)
            func_name = parts[0].strip()
            brief = parts[1].strip()
        elif line.startswith('@desc:'):
            mode = 'desc'
            desc_lines.append(line[len('@desc:'):].strip())
        elif line.startswith('@returns:'):
            mode = None
            returns = line[len('@returns:'):].strip()
        elif line.startswith('@param '):
            mode = None
            param_line = line[len('@param '):].strip()
            parts = param_line.split(' ', 1)
            if len(parts) == 2:
                param_name = parts[0].strip()
                param_desc = parts[1].strip()
                params.append((param_name, param_desc))
            else:
                params.append((parts[0], ""))
        elif line.startswith('@'):
            mode = None
        elif mode == 'desc':
            desc_lines.append(line)

    desc = ' '.join(desc_lines).strip()
    return func_name, brief, desc, params, returns

def extract_docs_from_file(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    docs = ['# API Documentation\n']
    i = 0
    first_signature = True
    while i < len(lines):
        if lines[i].strip().startswith('/**'):
            comment_lines = []
            i += 1 # ignore comment start
            while i < len(lines) and not lines[i].strip().endswith('*/'):
                comment_lines.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1

            # function signature
            signature_lines = []
            while i < len(lines):
                line = lines[i].strip()
                if '{' in line:
                    break
                signature_lines.append(line)
                i += 1

            signature = ' '.join(signature_lines)
            signature = signature.rstrip(' ')
            comment = '\n'.join(comment_lines)
            func_name, brief, desc, params, returns = parse_comment_block(comment)

            if not first_signature:
                markdown = f"---\n\n```c\n{signature}\n```\n\n"
            else:
                markdown = f"```c\n{signature}\n```\n\n"
            first_signature = False

            markdown += f"**Description**:\n{desc}\n"
            if params:
                markdown += "\n**Parameters**:\n\n"
                for name, description in params:
                    markdown += f"- *{name}*: {description}\n"
            if returns:
                markdown += f"\n**Returns**:\n{returns}\n"
            docs.append(markdown)
        else:
            i += 1

    return '\n'.join(docs)

if __name__ == "__main__":
    source_file = "hashMLDSA.c"
    output_file = "api_documentation.md"

    markdown = extract_docs_from_file(source_file)
    with open(output_file, 'w') as f:
        f.write(markdown)

    print(f"✅ API documentation has been generated in '{output_file}'.")
