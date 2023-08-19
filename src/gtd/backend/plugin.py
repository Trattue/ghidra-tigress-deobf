import shutil

PLUGINS_PATH = "plugins/"
TEMPLATE_PATH = PLUGINS_PATH + "_template_do_not_touch/"


def generate_plugin(vm_name: str, slaspec_content: str):
    # Create a copy of the template plugin. Error if directory already exists
    # TODO delete existing directory?
    new_path = PLUGINS_PATH + "tigress-" + vm_name + "/"
    shutil.copytree(TEMPLATE_PATH, new_path)

    # Copy stuff into slaspec
    languages = new_path + "data/languages/"
    with open(languages + "tigress.slaspec", "a") as slaspec:
        slaspec.write(slaspec_content)

    # Replace vm name placeholder
    targets = [
        languages + "tigress.ldefs",
        languages + "tigress.pspec",
        new_path + ".project",
    ]
    for target in targets:
        with open(target, "r") as file:
            content = file.read()
        content = content.replace("%NAME%", vm_name)
        with open(target, "w") as file:
            file.write(content)

    print(f"[*] Generated plugin tigress-{vm_name}\n")
