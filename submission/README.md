# Vibe Coding Agency - Hiring Test Submissions

This directory contains all completed test submissions in **Markdown format** with **PlantUML diagrams**.

## 📋 Submission Files

| File | Test | Description |
|------|------|-------------|
| `cloud-test.md` | Cloud Test | RAG system architecture for enterprise knowledge management |
| `security-test.md` | Security Test | Vulnerability analysis report with 11 identified issues |
| `application-test.md` | Application Test | AI-powered code review and deployment pipeline design |
| `security-fixed-code.zip` | Security Test | Remediated Python code with security fixes |

---

## 🎯 Why Markdown Instead of PDF?

The original PDF submissions had formatting issues with content overflowing page margins in tables and code blocks. To give you full control over PDF rendering and formatting, all submissions are now provided as **well-structured Markdown files** with **PlantUML diagrams**.

**Benefits:**
- ✅ Full control over page layout and formatting
- ✅ Professional PlantUML diagrams (instead of ASCII art)
- ✅ Easy to customize styling, fonts, and spacing
- ✅ No content overflow issues
- ✅ Source files are version-controlled and readable

---

## 🚀 How to Generate PDFs

### Option 1: Using Pandoc + WeasyPrint (Recommended)

**Prerequisites:**
```bash
# Install Pandoc
# macOS: brew install pandoc
# Ubuntu: sudo apt install pandoc
# Windows: Download from https://pandoc.org/installing.html

# Install WeasyPrint
pip install weasyprint

# Install PlantUML (requires Java)
# macOS: brew install plantuml
# Ubuntu: sudo apt install plantuml
# Or download JAR from https://plantuml.com/download
```

**Step 1: Render PlantUML Diagrams**

```bash
# Navigate to submission directory
cd submission/

# Generate PNG images from PlantUML code blocks
# For cloud-test.md
plantuml -tpng cloud-test.md

# For security-test.md
plantuml -tpng security-test.md

# For application-test.md
plantuml -tpng application-test.md
```

Note: PlantUML will extract all `@startuml...@enduml` blocks and create PNG images.

**Step 2: Convert Markdown to PDF**

```bash
# Cloud Test
pandoc cloud-test.md \
  -f markdown \
  -t html \
  --css=style.css \
  --pdf-engine=weasyprint \
  -o cloud-test.pdf

# Security Test
pandoc security-test.md \
  -f markdown \
  -t html \
  --css=style.css \
  --pdf-engine=weasyprint \
  -o security-test.pdf

# Application Test
pandoc application-test.md \
  -f markdown \
  -t html \
  --css=style.css \
  --pdf-engine=weasyprint \
  -o application-test.pdf
```

**Optional: Create a CSS file for better styling**

Create `style.css` in the submission directory:

```css
/* style.css */
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    max-width: 100%;
    margin: 2cm;
    color: #333;
}

h1 {
    font-size: 24pt;
    color: #2c3e50;
    border-bottom: 2px solid #3498db;
    padding-bottom: 10pt;
    margin-top: 20pt;
}

h2 {
    font-size: 18pt;
    color: #34495e;
    margin-top: 16pt;
    border-bottom: 1px solid #bdc3c7;
    padding-bottom: 5pt;
}

h3 {
    font-size: 14pt;
    color: #555;
    margin-top: 12pt;
}

table {
    border-collapse: collapse;
    width: 100%;
    margin: 10pt 0;
    font-size: 9pt;
    table-layout: auto;
}

th {
    background-color: #3498db;
    color: white;
    padding: 8pt;
    text-align: left;
    font-weight: bold;
}

td {
    padding: 6pt 8pt;
    border: 1px solid #ddd;
    word-wrap: break-word;
    overflow-wrap: break-word;
}

tr:nth-child(even) {
    background-color: #f2f2f2;
}

code {
    background-color: #f4f4f4;
    padding: 2pt 4pt;
    border-radius: 3px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 9pt;
}

pre {
    background-color: #f8f8f8;
    border: 1px solid #ddd;
    border-left: 4px solid #3498db;
    padding: 10pt;
    overflow-x: auto;
    font-size: 9pt;
    line-height: 1.4;
}

pre code {
    background-color: transparent;
    padding: 0;
}

blockquote {
    border-left: 4px solid #3498db;
    padding-left: 15pt;
    margin-left: 0;
    color: #555;
    font-style: italic;
}

img {
    max-width: 100%;
    height: auto;
    display: block;
    margin: 10pt auto;
}

/* Prevent page breaks inside code blocks and tables */
pre, table {
    page-break-inside: avoid;
}

/* Add page breaks before h1 headings (except first) */
h1 {
    page-break-before: always;
}

h1:first-of-type {
    page-break-before: avoid;
}
```

---

### Option 2: Using Markdown Editors with PDF Export

#### Visual Studio Code
1. Install extension: "Markdown PDF" by yzane
2. Open markdown file
3. Right-click → "Markdown PDF: Export (pdf)"
4. Customize settings in `.vscode/settings.json`:
   ```json
   {
     "markdown-pdf.format": "A4",
     "markdown-pdf.margin.top": "2cm",
     "markdown-pdf.margin.bottom": "2cm",
     "markdown-pdf.margin.right": "2cm",
     "markdown-pdf.margin.left": "2cm"
   }
   ```

#### Typora
1. Open markdown file in Typora
2. File → Export → PDF
3. Adjust page settings in export dialog

#### Obsidian
1. Install "Pandoc Plugin"
2. Open markdown file
3. Command palette → "Pandoc Plugin: Export to PDF"

---

### Option 3: Using Online Tools

#### HackMD
1. Visit https://hackmd.io/
2. Create new note
3. Paste markdown content
4. Click "..." → "Print" → "Save as PDF"

#### Markdown to PDF (Web)
1. Visit https://www.markdowntopdf.com/
2. Upload markdown file
3. Download generated PDF

**Note:** Online tools may not properly render PlantUML diagrams. Use Option 1 for best results.

---

## 🖼️ PlantUML Diagram Rendering

### Option 1: Pre-render Diagrams as Images

```bash
# Extract PlantUML code blocks and render as PNG
plantuml -tpng cloud-test.md

# This creates image files like:
# cloud-test-diagram-1.png
# cloud-test-diagram-2.png
# etc.

# Update markdown to reference images:
# Replace:
#   ```plantuml ... ```
# With:
#   ![Diagram](cloud-test-diagram-1.png)
```

### Option 2: Use PlantUML Server

Replace PlantUML code blocks with server-rendered images:

```markdown
![Architecture Diagram](http://www.plantuml.com/plantuml/png/ENCODED_DIAGRAM)
```

To encode diagrams:
```bash
# Use PlantUML encoder: https://www.plantuml.com/plantuml/uml/
# Or use online encoder: https://plantuml-encoder.herokuapp.com/
```

### Option 3: Keep Code Blocks (for reviewers)

If you prefer to keep PlantUML as code blocks for reviewers to see the source, the markdown files are already formatted correctly. Diagrams can be rendered when viewing in tools that support PlantUML (like VS Code with PlantUML extension).

---

## 📦 What's Included in Each Submission

### Cloud Test (`cloud-test.md`)
- 9 comprehensive sections as required
- PlantUML diagrams for:
  - High-level RAG system architecture
  - Document ingestion pipeline flow
  - Query pipeline with retrieval logic
  - Security architecture with authentication
  - Network security diagram
  - Application layer components
  - Scaling strategy visualization
  - Risk matrix
- Complete cost breakdown tables
- Technology stack specifications
- ~580 lines of content

### Security Test (`security-test.md`)
- 11 vulnerability analyses (5 Critical, 4 High, 2 Medium)
- PlantUML diagrams for:
  - Vulnerability landscape overview
  - SQL injection attack flow
  - Secrets exposure attack flow
  - Man-in-the-middle attack flow
  - Security architecture before/after comparison
  - Remediation implementation layers
  - Testing strategy flowchart
  - Severity matrix
- Detailed remediation code examples
- Deployment checklist
- Compliance mapping table (PCI-DSS, GDPR, SOC2)
- ~1100 lines of content

### Application Test (`application-test.md`)
- Complete 4-part response:
  - Part A: 12-step problem decomposition
  - Part B: Detailed AI prompting strategies
  - Part C: Reusable system architecture
  - Part D: 6-month implementation roadmap
- PlantUML diagrams for:
  - Complete workflow pipeline (12 steps)
  - Parallel execution flow
  - Critical decision points
  - High-level system architecture (C4 model)
  - Plugin architecture for languages
  - Deployment adapter pattern
  - Configuration hierarchy
  - Compliance framework system
  - Continuous learning loop
  - 6-month roadmap timeline
  - Risk mitigation matrix
  - Tool integration architecture
  - Success metrics dashboard
- Comprehensive code examples
- Cost breakdown and ROI analysis
- ~1400 lines of content

### Security Fixed Code (`security-fixed-code.zip`)
- `security_fixed_code.py` - Fully remediated Python code
- `README_SECURITY_FIXES.md` - Setup and verification instructions
- All 11 vulnerabilities fixed
- Production-ready code with:
  - Environment variable secrets management
  - Parameterized SQL queries
  - SSL/TLS validation enabled
  - Password hashing with bcrypt
  - Field-level encryption
  - Rate limiting
  - Input validation
  - Sanitized logging

---

## ✅ Verification Checklist

Before submitting PDFs, verify:

- [ ] All PlantUML diagrams render correctly
- [ ] Tables fit within page margins
- [ ] Code blocks don't overflow
- [ ] Headers and page breaks are appropriate
- [ ] Images are clear and readable
- [ ] File sizes are reasonable (< 5MB each)
- [ ] All sections from requirements are present

---

## 🛠️ Troubleshooting

### Issue: PlantUML diagrams don't render

**Solution:**
- Install PlantUML and Java
- Use online PlantUML renderer: https://www.plantuml.com/plantuml/uml/
- Or use VS Code extension: "PlantUML" by jebbs

### Issue: Tables overflow page margins

**Solution:**
- Adjust CSS `table { font-size: 8pt; }` for smaller text
- Use landscape orientation: `pandoc --pdf-engine-opt=--pdf-page-size=a4-landscape`
- Split large tables into multiple smaller tables

### Issue: Code blocks overflow

**Solution:**
- Add to CSS: `pre { font-size: 8pt; word-wrap: break-word; }`
- Use smaller code font
- Break long lines in code examples

### Issue: WeasyPrint not found

**Solution:**
```bash
# Ensure Python and pip are updated
pip install --upgrade pip
pip install weasyprint

# On Ubuntu, you may need system dependencies:
sudo apt install python3-dev python3-pip python3-setuptools \
    python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

---

## 📚 Additional Resources

- **Pandoc Documentation:** https://pandoc.org/MANUAL.html
- **PlantUML Documentation:** https://plantuml.com/
- **WeasyPrint Documentation:** https://doc.courtbouillon.org/weasyprint/
- **Markdown Guide:** https://www.markdownguide.org/
- **PlantUML Online Editor:** https://www.plantuml.com/plantuml/uml/

---

## 📞 Questions?

If you have any questions about the submissions or need clarification on any section, please refer to the markdown files directly - they are fully documented and readable as-is.

All submissions meet 100% of the requirements specified in each test's README file.

---

**Submission Date:** November 2025
**Submitted By:** Claude (AI-Powered Code Review System)
**Status:** ✅ Complete - All tests finished with comprehensive documentation
