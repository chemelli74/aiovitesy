# aiovitesy

<p align="center">
  <a href="https://github.com/chemelli74/aiovitesy/actions/workflows/ci.yml?query=branch%3Amain">
    <img src="https://img.shields.io/github/actions/workflow/status/chemelli74/aiovitesy/ci.yml?branch=main&label=CI&logo=github&style=flat-square" alt="CI Status" >
  </a>
  <a href="https://codecov.io/gh/chemelli74/aiovitesy">
    <img src="https://img.shields.io/codecov/c/github/chemelli74/aiovitesy.svg?logo=codecov&logoColor=fff&style=flat-square" alt="Test coverage percentage">
  </a>
</p>
<p align="center">
  <a href="https://docs.astral.sh/uv/">
    <img src="https://img.shields.io/badge/packaging-uv-2A5BFF?style=flat-square" alt="uv">
  </a>
  <a href="https://github.com/ambv/black">
    <img src="https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square" alt="black">
  </a>
  <a href="https://pypi.org/project/prek/">
    <img src="https://img.shields.io/badge/prek-enabled-brightgreen?style=flat-square" alt="prek">
  </a>
</p>
<p align="center">
  <a href="https://pypi.org/project/aiovitesy/">
    <img src="https://img.shields.io/pypi/v/aiovitesy.svg?logo=python&logoColor=fff&style=flat-square" alt="PyPI Version">
  </a>
  <a href="https://pypi.org/project/aiovitesy/">
    <img src="https://img.shields.io/pypi/pyversions/aiovitesy.svg?style=flat-square&amp;logo=python&amp;logoColor=fff" alt="Supported Python versions">
  </a>
  <img src="https://img.shields.io/pypi/l/aiovitesy.svg?style=flat-square" alt="License">
</p>

---

**Source Code**: <a href="https://github.com/chemelli74/aiovitesy" target="_blank">https://github.com/chemelli74/aiovitesy </a>

---

Python library to control Vitesy devices

## Installation

Install this via pip (or your favourite package manager):

`pip install aiovitesy`

## Usage

```python
import asyncio

from aiohttp import ClientSession

from aiovitesy.api import VitesyApi


async def main() -> None:
    async with ClientSession() as session:
        api = VitesyApi("you@example.com", "your-password", session)
        await api.login()

        devices = await api.get_all_devices()
        for device in devices.values():
            print(device.name, device.program_id, device.measurement)


asyncio.run(main())
```

`VitesyApi` only reads data for now (devices, measurements, programs, maintenance);
changing the active program will be added in a later release.

## Test

Test the library with:

`python library_test.py`

The script accepts command line arguments or a `library_test.json` config file:

```json
{
  "username": "<your_username>",
  "password": "<your_password>"
}
```

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- prettier-ignore-start -->
<!-- readme: contributors -start -->
<table>
	<tbody>
		<tr>
            <td align="center">
                <a href="https://github.com/chemelli74">
                    <img src="https://avatars.githubusercontent.com/u/57354320?v=4" width="100;" alt="chemelli74"/>
                    <br />
                    <sub><b>Simone Chemelli</b></sub>
                </a>
            </td>
		</tr>
	<tbody>
</table>
<!-- readme: contributors -end -->
<!-- prettier-ignore-end -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## Credits

This package was created with
[Copier](https://copier.readthedocs.io/) and the
[browniebroke/pypackage-template](https://github.com/browniebroke/pypackage-template)
project template.
