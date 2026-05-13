from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional


@dataclass
class ParameterInfo:
    """함수 파라미터 정보"""
    name: str
    type: str
    ordinal: int
    storage: Optional[str] = None  # 레지스터 또는 스택 위치


@dataclass
class ApiCallInfo:
    """API 호출 정보"""
    name: str
    count: int = 1
    address: Optional[str] = None


@dataclass
class StringInfo:
    """문자열 정보"""
    value: str
    address: str
    length: int
    type: str = "string"


@dataclass
class XrefInfo:
    """Cross-Reference 상세 정보"""
    internal_calls: int = 0
    external_references: int = 0
    data_references: int = 0
    flow_references: int = 0
    fallthrough: int = 0


@dataclass
class SizeMetrics:
    """함수 크기 관련 메트릭"""
    body_size: int
    num_instructions: int = 0
    num_basic_blocks: int = 0
    cyclomatic_complexity: int = 1
    is_leaf_function: bool = False
    is_entry_point: bool = False


@dataclass
class FunctionInfo:
    """통합 함수 정보 - 확장 버전"""
    name: str
    entry: str

    # 기본 정보
    body_size: int
    calls: List[str]
    called_by: List[str]

    # 확장된 정보
    parameters: List[ParameterInfo] = field(default_factory=list)
    return_type: str = "unknown"

    # 상세 참조 정보
    xrefs: XrefInfo = field(default_factory=XrefInfo)
    api_calls: Dict[str, int] = field(default_factory=dict)
    strings: List[StringInfo] = field(default_factory=list)

    # 추가 메트릭
    metrics: SizeMetrics = field(default_factory=lambda: SizeMetrics(body_size=0))

    # 하위 호환성 위한 프로퍼티
    @property
    def xrefs_in(self) -> int:
        return self.xrefs.internal_calls + self.xrefs.external_references

    @property
    def xrefs_out(self) -> int:
        return self.xrefs.flow_references + self.xrefs.fallthrough

    @property
    def api_calls_list(self) -> List[str]:
        """API 호출명 리스트 (기존 호환성)"""
        return sorted(self.api_calls.keys())

    @property
    def strings_list(self) -> List[str]:
        """문자열 값 리스트 (기존 호환성)"""
        return [s.value for s in self.strings]

    @property
    def parameters_list(self) -> List[str]:
        """파라미터 타입 리스트 (기존 호환성)"""
        return [p.type for p in self.parameters]

    def to_dict(self) -> dict:
        """JSON 직렬화용 딕셔너리 변환"""
        return {
            "name": self.name,
            "entry": self.entry,
            "body_size": self.body_size,
            "calls": self.calls,
            "called_by": self.called_by,
            "xrefs_in": self.xrefs_in,
            "xrefs_out": self.xrefs_out,
            "api_calls": self.api_calls_list,
            "api_call_details": self.api_calls,
            "strings": self.strings_list,
            "strings_detailed": [asdict(s) for s in self.strings],
            "parameters": self.parameters_list,
            "parameters_detailed": [asdict(p) for p in self.parameters],
            "return_type": self.return_type,
            "metrics": asdict(self.metrics),
            "xrefs_detailed": asdict(self.xrefs),
        }