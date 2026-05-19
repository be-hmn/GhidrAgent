# GhidraMCP

Pyhidra 기반의 Headless Ghidra 자동 분석 프레임워크입니다.

GhidraMCP는 다음 과정을 자동화합니다.

- Ghidra 프로젝트 생성
- 바이너리 Import
- Auto Analysis 실행
- 함수 순회(Function Iteration)
- API 추출
- 문자열(String) 추출
- Call Graph 추출
- JSON Export

현재는 경량 Reverse Engineering Metadata Pipeline 구조를 목표로 하며, 이후 다음과 같은 방향으로 확장 가능합니다.

- Capability Analysis
- Malware Triage
- Function Classification
- Semantic Analysis
- LLM 기반 Reverse Engineering
- Agent 기반 자동 분석

---

# 주요 기능

## 현재 구현

- Headless Ghidra 실행
- `.gpr` 프로젝트 자동 생성
- PE 바이너리 Import
- Auto Analysis 실행
- 함수 메타데이터 추출
- API Call 추출
- 문자열 참조 추출
- Caller / Callee 관계 추출
- JSON Export

---

## 향후 계획

- Decompiler Integration
- PCode Extraction
- CFG 생성
- Capability Tagging
- Symbolic Reasoning
- LLM 기반 Semantic Analysis
- Malware Behavior Clustering

---

# 프로젝트 구조

```text
GhidraMCP/
├── analyzer/
│   ├── extractors/
│   │   └── function_data.py
│   └── runtime.py
│
├── output/
│   └── {BINARY_NAME}.json
│
├── .binary/
│   └── target.exe
│
├── .ghidra_projects/
│
├── main.py
├── pyproject.toml
├── uv.lock
└── README.md
```

---

# 권장 환경

| 구성 요소 | 버전 |
|---|---|
| Python | 3.11.x |
| Java | JDK 21 |
| Ghidra | 11.x |
| OS | Windows 11 |

---

# 설치 방법

## 1. Repository Clone

```bash
git clone https://github.com/be-hmn/GhidraMCP.git

cd GhidraMCP
```

---

## 2. uv 설치

```bash
pip install uv
```

---

## 3. 가상환경 생성

```bash
uv venv --python 3.11
```

---

## 4. 가상환경 활성화

### CMD

```cmd
.venv\Scripts\activate.bat
```

### PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

---

## 5. 의존성 설치

### CLI 모드

```bash
uv sync
```

### MCP 서버 모드

```bash
uv sync
pip install mcp  # MCP SDK
```

---

# 환경 변수 설정

프로젝트 루트에 `.env` 생성

```env
GHIDRA_HOME={ghidra_install_path}
TARGET_BINARY=.binary\{target_binary_name}

PROJECT_DIR=.ghidra_projects
PROJECT_NAME=GhidraMCPProject_{binary_name}
```

---

# IntelliJ 설정

## Python SDK

다음 경로 사용

```text
.venv\Scripts\python.exe
```

---

## Terminal 설정

권장:

```text
cmd.exe /k ".venv\Scripts\activate.bat"
```

---

## Java 환경 변수

```text
JAVA_HOME=C:\Program Files\Java\jdk-21
PATH=C:\Program Files\Java\jdk-21\bin;%PATH%
```

---

# 실행 방법

## CLI 모드 (기본값)

### 분석 실행

```bash
python main.py cli --binary {binary_path}
```

또는 환경변수 사용:

```bash
python main.py cli
```

### MCP 출력 스모크 검사

```bash
python scripts\mcp_smoke.py --input output\Easy_CrackMe.json
```

---

## MCP 서버 모드

GhidraMCP는 Model Context Protocol(MCP) 서버로도 실행할 수 있습니다.

### MCP 서버 시작

```bash
# stdio 모드 (권장)
python main.py mcp

# SSE 모드 (특정 포트)
python main.py mcp --port 8000
```

### MCP 도구

MCP 서버는 다음 도구를 제공합니다:

#### 1. `analyze_binary` - 바이너리 분석

```json
{
  "name": "analyze_binary",
  "arguments": {
    "ghidra_home": "/path/to/ghidra",
    "binary_path": "/path/to/binary",
    "project_dir": ".ghidra_projects",
    "project_name": "MyProject"
  }
}
```

#### 2. `get_analysis_result` - 분석 결과 조회 (캐시)

```json
{
  "name": "get_analysis_result",
  "arguments": {
    "binary_path": "/path/to/binary"
  }
}
```

#### 3. `validate_mcp_output` - MCP 출력 검증

```json
{
  "name": "validate_mcp_output",
  "arguments": {
    "output_path": "/path/to/output.json"
  }
}
```

### MCP 리소스

#### `ghidra://binaries` - 분석된 바이너리 목록

```json
{
  "uri": "ghidra://binaries",
  "name": "Available Binaries",
  "mimeType": "application/json"
}
```

---

# 출력 결과 예시

```json
{
  "name": "FUN_00401080",
  "body_size": 205,
  "calls": [
    "EndDialog",
    "GetDlgItemTextA",
    "MessageBoxA"
  ],
  "api_calls": [
    "MessageBoxA"
  ],
  "strings": [
    "Incorrect Password",
    "Congratulation !!"
  ],
  "call_sequence": [
    {
      "index": 0,
      "target": "GetDlgItemTextA",
      "description": "입력 받기"
    }
  ]
}
```

---

# 현재 추출되는 데이터

| 항목 | 설명 |
|---|---|
| name | 함수 이름 |
| body_size | 함수 크기 |
| calls | 내부 함수 호출 |
| called_by | 호출한 함수 |
| api_calls | 사용된 외부 API |
| custom_calls | 사용자 정의/비표준 외부 호출 |
| strings | 참조 문자열 |
| parameters | 함수 파라미터 |
| return_type | 반환 타입 |
| metrics | 복잡도 및 메트릭 |
| call_sequence | 함수 내 호출 순서 |

---

# Runtime 동작 흐름

```text
Pyhidra 초기화
        ↓
Ghidra Project 생성/Open
        ↓
Binary Import
        ↓
Auto Analysis 실행
        ↓
함수 순회
        ↓
Metadata 추출
        ↓
JSON Export
```

---

# 분석 흐름 예시

```text
Binary
 ↓
Ghidra Auto Analysis
 ↓
Function Metadata Extraction
 ↓
Call Graph 생성
 ↓
Semantic Analysis
 ↓
LLM / Agent Pipeline
```

---

# Known Issues

## Headless Analyzer Warning

일부 Ghidra Analyzer는 Headless 환경에서 다음 Warning을 출력할 수 있습니다.

```text
bundleHost is null
```

이는 GUI 기반 Analyzer가 Headless 환경에서 동작하면서 발생하는 경고이며, 일반적인 Metadata Extraction에는 큰 영향을 주지 않습니다.

---

# 개발 방향

현재 프로젝트는 다음 방향을 목표로 확장 중입니다.

- Reverse Engineering 자동화
- Semantic Binary Analysis
- Malware Capability Extraction
- AI 기반 분석 Pipeline
- Autonomous Analysis Agent

---

# License

MIT License
