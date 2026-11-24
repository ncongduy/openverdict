from openverdict.cli import main


def test_create_and_revoke_key(db_url, monkeypatch, capsys):
    monkeypatch.setenv("OPENVERDICT_DATABASE_URL", db_url)
    assert main(["migrate"]) == 0
    assert main(["create-key", "--name", "cli-app", "--role", "client"]) == 0
    assert capsys.readouterr().out.strip().startswith("ov_")
    assert main(["revoke-key", "--name", "cli-app"]) == 0
    assert main(["revoke-key", "--name", "cli-app-missing"]) == 1
    assert main(["create-key", "--name", "x", "--role", "admin"]) == 2
