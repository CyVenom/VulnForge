import asyncio

from core.plugin_manager import PROJECT_ROOT, PluginManager


def load(cfg):
    pm = PluginManager({"plugins": cfg})
    asyncio.run(pm.load_plugins())
    return pm


def test_relative_plugin_dir_ignores_the_current_directory(tmp_path, monkeypatch):
    evil = tmp_path / "plugins"
    evil.mkdir()
    marker = tmp_path / "pwned.txt"
    (evil / "plugin_evil.py").write_text(f"open({str(marker)!r}, 'w').write('ran')\n")
    monkeypatch.chdir(tmp_path)

    pm = load({"enabled": True, "dir": "plugins"})

    assert not marker.exists(), "code from the current directory was executed"
    assert "dns_recon" in pm.plugins  # the real plugins still load


def test_absolute_plugin_dir_is_still_honoured(tmp_path):
    (tmp_path / "plugin_mine.py").write_text(
        "from core.plugin_manager import VulnForgePlugin\n"
        "class Mine(VulnForgePlugin):\n"
        "    name = 'mine'\n"
        "    async def run(self, target, scan_result):\n"
        "        return {'findings': []}\n"
    )
    pm = load({"enabled": True, "dir": str(tmp_path)})
    assert list(pm.plugins) == ["mine"]


def test_project_root_points_at_the_install():
    assert (PROJECT_ROOT / "vulnforge.py").exists()
