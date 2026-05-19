"""프로젝트 관리 및 동시성 제어"""

import hashlib
import logging
import threading
from pathlib import Path
from contextlib import contextmanager
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ProjectLockManager:
    """Ghidra 프로젝트 동시성 제어 및 캐싱"""

    def __init__(self, cache_ttl_hours: int = 24):
        """
        Args:
            cache_ttl_hours: 캐시 유효 시간 (시간 단위)
        """
        self._locks: Dict[str, threading.RLock] = {}
        self._lock = threading.RLock()

        # 분석 결과 캐시
        self._analysis_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = timedelta(hours=cache_ttl_hours)

    def acquire_lock(self, project_name: str) -> "LockContextManager":
        """프로젝트별 잠금 획득

        Args:
            project_name: 프로젝트 이름

        Returns:
            LockContextManager: 컨텍스트 매니저
        """
        with self._lock:
            if project_name not in self._locks:
                self._locks[project_name] = threading.RLock()

        return LockContextManager(self._locks[project_name])

    def cache_analysis(self, binary_path: str, results: List[Dict]) -> None:
        """분석 결과 캐싱

        Args:
            binary_path: 바이너리 파일 경로
            results: 분석 결과 리스트
        """
        cache_key = self._get_cache_key(binary_path)

        with self._lock:
            self._analysis_cache[cache_key] = {
                "timestamp": datetime.now(),
                "binary_path": binary_path,
                "results": results,
            }

        logger.info(f"Cached analysis for: {binary_path}")

    def get_cached_analysis(self, binary_path: str) -> Optional[List[Dict]]:
        """캐시된 분석 결과 조회

        Args:
            binary_path: 바이너리 파일 경로

        Returns:
            분석 결과 또는 None (캐시 없거나 만료됨)
        """
        cache_key = self._get_cache_key(binary_path)

        with self._lock:
            if cache_key not in self._analysis_cache:
                return None

            cache_entry = self._analysis_cache[cache_key]

            # TTL 확인
            if datetime.now() - cache_entry["timestamp"] > self._cache_ttl:
                logger.info(f"Cache expired for: {binary_path}")
                del self._analysis_cache[cache_key]
                return None

            logger.info(f"Using cached analysis for: {binary_path}")
            return cache_entry["results"]

    def list_analyzed_binaries(self) -> List[Dict[str, str]]:
        """분석된 바이너리 목록 조회

        Returns:
            분석된 바이너리 정보 리스트
        """
        with self._lock:
            return [
                {
                    "binary_path": entry["binary_path"],
                    "timestamp": entry["timestamp"].isoformat(),
                    "function_count": len(entry["results"]),
                }
                for entry in self._analysis_cache.values()
            ]

    def clear_cache(self) -> None:
        """캐시 전체 삭제"""
        with self._lock:
            self._analysis_cache.clear()
        logger.info("Analysis cache cleared")

    def invalidate_cache(self, binary_path: str) -> None:
        """특정 바이너리의 캐시 삭제

        Args:
            binary_path: 바이너리 파일 경로
        """
        cache_key = self._get_cache_key(binary_path)

        with self._lock:
            if cache_key in self._analysis_cache:
                del self._analysis_cache[cache_key]

        logger.info(f"Cache invalidated for: {binary_path}")

    @staticmethod
    def _get_cache_key(binary_path: str) -> str:
        """바이너리 경로에서 캐시 키 생성

        Args:
            binary_path: 바이너리 파일 경로

        Returns:
            캐시 키
        """
        path = Path(binary_path).resolve()
        # 파일 크기와 경로를 기반으로 고유 키 생성
        identifier = f"{path}:{path.stat().st_size}"
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]


class LockContextManager:
    """Threading Lock용 컨텍스트 매니저"""

    def __init__(self, lock: threading.RLock):
        """
        Args:
            lock: 사용할 RLock 객체
        """
        self.lock = lock

    def __enter__(self) -> "LockContextManager":
        """잠금 획득"""
        self.lock.acquire()
        logger.debug("Lock acquired")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """잠금 해제"""
        self.lock.release()
        logger.debug("Lock released")

