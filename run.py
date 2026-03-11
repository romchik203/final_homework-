"""
Единая точка входа: запуск веб-дашборда мониторинга угроз.
Запустите:  python run.py
В браузере откроется Streamlit с результатами и возможностью запуска анализа.
"""

import os
import subprocess
import sys
from pathlib import Path

# Корень проекта — каталог, где лежит run.py
PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)


def main() -> None:
    app_path = PROJECT_ROOT / "app.py"
    if not app_path.exists():
        print("Ошибка: app.py не найден в каталоге проекта.", file=sys.stderr)
        sys.exit(1)
    # Запуск Streamlit через текущий интерпретатор (не зависит от PATH)
    result = subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path)],
        cwd=PROJECT_ROOT,
    )
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
