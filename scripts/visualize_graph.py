from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from graph_app import soc_app


def main() -> None:
    # Save to root artifacts folder, not scripts/artifacts
    out_dir = Path(__file__).parent.parent / "artifacts"
    out_dir.mkdir(exist_ok=True)

    graph = soc_app.get_graph()

    mermaid = graph.draw_mermaid()
    mermaid_path = out_dir / "langgraph.mmd"
    mermaid_path.write_text(mermaid, encoding="utf-8")

    png_path = out_dir / "langgraph.png"
    try:
        png_bytes = graph.draw_mermaid_png()
    except Exception as exc:
        print("Could not render PNG. Mermaid source saved to:", mermaid_path)
        print("Error:", exc)
        return

    png_path.write_bytes(png_bytes)
    print("Graph rendered to:", png_path)


if __name__ == "__main__":
    main()
