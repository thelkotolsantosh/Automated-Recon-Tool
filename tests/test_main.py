import json
from unittest.mock import patch

from recon.main import main


def test_selected_modules_are_saved_in_one_report(tmp_path):
    wordlist = tmp_path / 'paths.txt'
    wordlist.write_text('index.html\n')
    report = tmp_path / 'report.json'
    args = ['main.py', '-t', 'example.com', '--all', '--wordlist', str(wordlist), '-o', str(report)]
    with patch('sys.argv', args), patch('recon.main.SubdomainScanner') as subdomains, \
            patch('recon.main.PortScanner') as ports, patch('recon.main.DirFuzzer') as directories:
        subdomains.return_value.run.return_value = []
        ports.return_value.run.return_value = []
        directories.return_value.run.return_value = []
        main()
    result = json.loads(report.read_text())
    assert result['target'] == 'example.com'
    assert result['summary']['total_open_ports'] == 0
    subdomains.return_value.run.assert_called_once()
    ports.return_value.run.assert_called_once()
    directories.return_value.run.assert_called_once()
