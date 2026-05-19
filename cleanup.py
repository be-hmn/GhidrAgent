# cleanup.py
import os
from pathlib import Path
import shutil

def cleanup_project():
    root = Path("C:\\Users\\NYH\\IdeaProjects\\GhidrAgent")

    # 삭제할 파일
    files_to_delete = [
        ".env.example",
        "requirements.txt",
        "run.log",
        "MIGRATION_SUMMARY.txt",
        "FINAL_SUMMARY.md",
        "MCP_COMPLETION_REPORT.md",
        "MCP_MIGRATION.md",
        "PROJECT_OVERVIEW.md",
        "QUICKSTART.md",
        "rename.py",
        "1.0.0",
    ]

    # 삭제할 폴더
    dirs_to_delete = [
        "benchmarks",
    ]

    # 파일 삭제
    print("🗑️  파일 삭제 중...")
    for file in files_to_delete:
        filepath = root / file
        if filepath.exists():
            filepath.unlink()
            print(f"  ✅ {file} 삭제됨")

    # 폴더 삭제
    print("\n🗑️  폴더 삭제 중...")
    for dir_name in dirs_to_delete:
        dirpath = root / dir_name
        if dirpath.exists():
            shutil.rmtree(dirpath)
            print(f"  ✅ {dir_name}/ 삭제됨")

    # scripts 폴더 정리
    scripts_dir = root / "scripts"
    if (scripts_dir / "score_benchmark.py").exists():
        (scripts_dir / "score_benchmark.py").unlink()
        print(f"  ✅ scripts/score_benchmark.py 삭제됨")

    print("\n✨ 정리 완료!")

if __name__ == "__main__":
    cleanup_project()