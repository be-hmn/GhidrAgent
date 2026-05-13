# GhidrAgent - LLM-Friendly Binary Analysis Framework

> Ghidra 기반 자동화된 바이너리 분석 도구로, 리버스 엔지니어링 및 악성코드 분석을 위한 풍부한 메타데이터를 생성합니다.

## 🎯 목표

**Phase 1 ✅ 완료:**
- Ghidra를 이용한 바이너리 함수 자동 추출
- 기본 함수 메타데이터 수집

**Phase 2 ✅ 완료:**
- 의미론적 메타데이터 풍부화 (Semantic Enrichment)
- 함수 간 호출 관계 추출
- API 호출 및 문자열 참조 분석
- 자동 기능 탐지 (Capabilities Detection)

**Phase 3 🔄 진행 중:**
- LLM 기반 함수 분류 및 우선순위 결정
- 자동 함수 이름 생성
- 악의적 패턴 탐지

**Phase 4 계획 중:**
- AI 에이전트 기반 자동 역분석
- 함수별 Pseudo Code 추출

**Phase 5 비전:**
- 완전 자동화된 악성코드 분석 파이프라인

---

## 🚀 빠른 시작

### 1. 환경 설정

#### 필수 요구사항
- Python 3.10+
- Ghidra 12.0+
- Windows (현재 테스트는 Windows에서만 진행)

#### 설치 단계

```bash
# 1. 저장소 클론
git clone https://github.com/yourusername/GhidrAgent.git
cd GhidrAgent

# 2. Python 3.14 설치 (또는 기존 Python 사용)
# https://www.python.org/downloads/

# 3. 가상환경 생성
python -m venv .venv

# 4. 가상환경 활성화 (Windows)
.\.venv\Scripts\Activate.ps1

# 5. 의존성 설치
python -m pip install --upgrade pip
python -m pip install -r requirements.txt