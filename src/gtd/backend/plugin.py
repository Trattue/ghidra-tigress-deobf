from pathlib import Path
import shutil

PLUGINS_PATH = Path("plugins/")
TEMPLATE_PATH = PLUGINS_PATH.joinpath("_template_do_not_touch/")


def generate_plugin(vm_name: str, slaspec_content: str):
    # Create a copy of the template plugin. Error if directory already exists
    # TODO delete existing directory?
    new_path = PLUGINS_PATH.joinpath(f"tigress-{vm_name}/")
    shutil.copytree(TEMPLATE_PATH, new_path)

    # Copy stuff into slaspec
    languages = new_path.joinpath("data/languages/")
    with languages.joinpath("tigress.slaspec").open("a") as slaspec:
        slaspec.write(slaspec_content)

    # Replace vm name placeholder
    targets = [
        languages.joinpath("tigress.ldefs"),
        languages.joinpath("tigress.pspec"),
        new_path.joinpath(".project"),
        new_path.joinpath("ghidra_scripts/Export.java"),
    ]
    for target in targets:
        with target.open("r") as file:
            content = file.read()
        content = content.replace("%NAME%", vm_name)
        with target.open("w") as file:
            file.write(content)

    print(f"[*] Generated plugin tigress-{vm_name}\n")
