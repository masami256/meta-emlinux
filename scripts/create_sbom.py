#!/usr/bin/python3

import argparse
import sys
import os, os.path
import io
from debian import copyright
import debian.debfile
from debian.deb822 import Packages
import json
import yaml
import glob
import hashlib
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), "lib/python"))
sys.path.append(os.path.join(os.path.dirname(__file__), "lib/python/sbom"))

import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s:%(levelname)s: %(message)s")
logger = logging.getLogger("emlinux-sbom-creator")

import bitbake_runner
import sbom_cyclonedx
import sbom_spdx
import licensing
import pprint

# Only show critical error from debian copyright library
copyright.logger.setLevel(logging.CRITICAL)

import re

def strip_outer_parentheses(text):
    text = text.strip()
    while text.startswith('(') and text.endswith(')'):
        depth = 0
        is_outer = True
        for i, char in enumerate(text[:-1]):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            if depth == 0 and i > 0:
                is_outer = False
                break

        if is_outer:
            text = text[1:-1].strip()
        else:
            break
    return text

def parse_to_license_array(expression):
    tokens = re.split(r'(\(|\)|\s+)', expression)
    
    elements = []
    current_element = []
    depth = 0

    for token in tokens:
        if not token:
            continue

        if token == '(':
            depth += 1
            current_element.append(token)
        elif token == ')':
            depth -= 1
            current_element.append(token)
        elif depth == 0 and token.strip().upper() == 'AND':
            elem_str = "".join(current_element).strip()
            if elem_str:
                elements.append(elem_str)
            current_element = []
        else:
            current_element.append(token)

    last_elem_str = "".join(current_element).strip()
    if last_elem_str:
        elements.append(last_elem_str)

    return [strip_outer_parentheses(elem) for elem in elements]

def normalize_license_name(raw_name, license_mapping):
    cleaned = raw_name.strip()
    lower_name = cleaned.lower()

    if lower_name in license_mapping:
        return license_mapping[lower_name]

    return raw_name

def tokenize(expression: str):
    pattern = r'(\(|\)|\bAND\b|\bOR\b|&|\|)'
    raw_tokens = re.split(pattern, expression, flags=re.IGNORECASE)
        
    tokens = []
    for t in raw_tokens:
        if not t or t.isspace():
            continue
        t_str = t.strip()
        if t_str == '&':
            tokens.append('AND')
        elif t_str == '|':
           tokens.append('OR')
        elif t_str.upper() in ('AND', 'OR'):
           tokens.append(t_str.upper())
        else:
           tokens.append(t_str)
    return tokens

def parse_to_ast(tokens, license_mapping):
    precedence = {'OR': 1, 'AND': 2}
    output_stack = []
    operator_stack = []
    licenses = []

    for token in tokens:
        if token in ('AND', 'OR'):
            while (operator_stack and operator_stack[-1] != '(' and
                   precedence.get(operator_stack[-1], 0) >= precedence[token]):
                op = operator_stack.pop()
                right = output_stack.pop()
                left = output_stack.pop()
                output_stack.append((op, left, right))
            operator_stack.append(token)
        elif token == '(':
            operator_stack.append(token)
        elif token == ')':
            while operator_stack and operator_stack[-1] != '(':
                op = operator_stack.pop()
                right = output_stack.pop()
                left = output_stack.pop()
                output_stack.append((op, left, right))
            if operator_stack and operator_stack[-1] == '(':
                operator_stack.pop()
        else:
            normalized_id = normalize_license_name(token, license_mapping)
            output_stack.append(normalized_id)
            licenses.append(normalized_id)

    while operator_stack:
       op = operator_stack.pop()
       right = output_stack.pop()
       left = output_stack.pop()
       output_stack.append((op, left, right))

    return output_stack[0] if output_stack else ""

def ast_to_spdx(node, parent_op=None):
    if isinstance(node, str):
        return node

    op, left, right = node
    left_str = ast_to_spdx(left, op)
    right_str = ast_to_spdx(right, op)

    res = f"{left_str} {op} {right_str}"

    precedence = {'OR': 1, 'AND': 2}
    if parent_op and precedence[op] < precedence[parent_op]:
        res = f"({res})"
    elif parent_op and parent_op != op:
        res = f"({res})"

    return res

def normalize_licese_field(raw_license, license_mapping):
    tokens = tokenize(raw_license)
    ast = parse_to_ast(tokens, license_mapping)
    return ast_to_spdx(ast)

def merge_package_data(installed_pkgs, packages_info):
    for pkg in installed_pkgs:
        if pkg in packages_info:
            installed_pkgs[pkg]["sha256sum"] = packages_info[pkg]["sha256sum"]
            installed_pkgs[pkg]["description"] = packages_info[pkg]["description"]

    return installed_pkgs


def find_deb_packages(dl_dir, repo_isar_dir, distro, image_distro):
    targets = [
        f"{dl_dir}/deb/debian-{distro}/*.deb",
        f"{repo_isar_dir}/{image_distro}/pool/**/*.deb",
    ]

    ret = []

    for target in targets:
        ret += glob.glob(target, recursive=True)

    return ret


def get_package_info_from_control(
    dl_dir, repo_isar_dir, distro, image_distro, distro_arch
):
    ret = {}

    debs = find_deb_packages(dl_dir, repo_isar_dir, distro, image_distro)
    for debfile in debs:
        pkgname = None
        with debian.debfile.DebFile(debfile) as deb:
            control = deb.debcontrol()
            pkgname = control.get("Package", "Unknown")
            arch = control.get("Architecture", "Unknown")
            desc = control.get("Description", "No description")

            if arch == distro_arch or arch == "all":
                sha256sum = None
                sha256hash = hashlib.sha256()
                with open(debfile, "rb") as f:
                    for block in iter(lambda: f.read(4096), b""):
                        sha256hash.update(block)
                        sha256sum = sha256hash.hexdigest()
                ret[pkgname] = {
                    "sha256sum": sha256sum,
                    "description": desc,
                }

    return ret


def parse_copyright_file(copyright_file):
    licenses = {}

    with io.open(copyright_file, "rt", encoding="utf-8") as f:
        try:
            c = copyright.Copyright(f, strict=False)
        except Exception:
            logger.debug(
                f"Read copyright file error for {copyright_file}. May be this file uses old foromat."
            )
        else:
            for p in c.all_files_paragraphs():
                if p.license and p.license.synopsis:
                    licenses.setdefault("synopsis", []).append(p.license.synopsis)
                    if len(p.license.text) > 0:
                        licenses.setdefault("text", {})[
                            p.license.synopsis
                        ] = p.license.text
            for text in c.all_license_paragraphs():
                if text.license:
                    licenses.setdefault("text", {})[
                        text.license.synopsis
                    ] = text.license.text

    return licenses


def parse_dpkg_status(dpkgstatus):
    ret = {}

    with open(dpkgstatus, "r") as f:
        for pkg in Packages.iter_paragraphs(f, use_apt_pkg=False):
            d = {}

            d["package"] = pkg.get("Package")
            d["source"] = pkg.get("Source")
            d["version"] = pkg.get("Version")
            d["maintainer"] = pkg.get("Maintainer")
            d["section"] = pkg.get("Section")
            d["homepage"] = pkg.get("Homepage", "No Homepage")
            d["arch"] = pkg.get("Architecture")
            if d["source"] is None:
                d["source"] = d["package"]
            d["description"] = pkg.get("Description", "No description")
            
            ret[d["package"]] = d

    return ret


def read_copyright_files(rootfs, installed_pkgs, user_defined_licenses):
    for pkg in installed_pkgs:
        logger.debug(f"Checking copyright for {pkg}")
        path = f"{rootfs}/usr/share/doc/{installed_pkgs[pkg]['package']}/copyright"

        if os.path.exists(path):
            licenses = parse_copyright_file(path)
            if bool(licenses):
                installed_pkgs[pkg]["licenses"] = licenses
        # else:
        #    logger.warning(f"Packge {pkg} does not contain copyright file")

        # When failed to parse copyright file or package name is in user defined license file,
        # set license from license defined file
        if not "licenses" in installed_pkgs[pkg] or pkg in user_defined_licenses:
            logger.debug(f"Check user defined mapping file for {pkg}")
            if pkg in user_defined_licenses:
                logger.debug(f"found {pkg} in user defined license file")
                synopsis = user_defined_licenses[pkg]["synopsis"]

                installed_pkgs[pkg]["licenses"] = {
                    "synopsis": synopsis,
                    "text": {},
                }

                for lic_name in user_defined_licenses[pkg]["license_data"]:
                    lic_data = user_defined_licenses[pkg]["license_data"][lic_name]
                    installed_pkgs[pkg]["licenses"]["text"][lic_name] = lic_data["text"]

        if not "licenses" in installed_pkgs[pkg]:
            logger.warning(
                f"{pkg}: Cannot get licenses from Copyright file and user defined license mapping file. So, set NOASSERTION as license."
            )
            installed_pkgs[pkg]["licenses"] = {"synopsis": ["NOASSERTION"], "text": {}}


def make_user_defined_license_data(yml_file_name):
    license_data = {}
    data = None
    with open(yml_file_name, "r") as f:
        data = yaml.safe_load(f)

    if data is None:
        return license_data

    for pkg in data:
        license_data[pkg] = {"license_data": {}, "synopsis": {}}

        pkg_data = data[pkg]
        typename = type(pkg_data["licenses"])
        # logger.debug(f"{pkg} data type {typename}")
        if typename == dict:
            for synopsis in pkg_data["licenses"]["license"]:
                lic_text_path = None
                lic_text = None

                licenses = licensing.split_synopsis_tokens_only(synopsis)
                for lic_name in licenses:
                    if lic_name in pkg_data["licenses"]["text"]:
                        lic_text_path = pkg_data["licenses"]["text"].get(lic_name)

                    if lic_text_path is not None:
                        lic_text_path = Path(lic_text_path)
                        if not lic_text_path.is_absolute():
                            lic_text_path = yml_file_name.parent.joinpath(
                                "license_texts", lic_text_path
                            )

                        if not lic_text_path.exists():
                            logger.error(
                                f"License file  {lic_text_path} for {pkg} doesn't exist"
                            )
                            exit(1)
                        logger.debug(
                            f"{pkg} read license {lic_name} text from {lic_text_path}"
                        )
                        with open(lic_text_path) as f:
                            lic_text = f.read()

                    license_data[pkg]["license_data"][lic_name] = {
                        "synopsis": synopsis,
                        "licenses": licenses,
                        "text": lic_text,
                    }

        elif typename == list:
            for lic_name in pkg_data["licenses"]:
                license_data[pkg]["license_data"][lic_name] = {
                    "synopsis": lic_name,
                    "licenses": licensing.split_synopsis_tokens_only(lic_name),
                    "text": None,
                }
        elif typename == str:
            lic_name = pkg_data["licenses"]
            license_data[pkg]["license_data"][lic_name] = {
                "synopsis": lic_name,
                "licenses": licensing.split_synopsis_tokens_only(lic_name),
                "text": None,
            }

        synopsis = []
        for lic_name in license_data[pkg]["license_data"]:
            s = license_data[pkg]["license_data"][lic_name]["synopsis"]
            if not s in synopsis:
                synopsis.append(s)

        license_data[pkg]["synopsis"] = synopsis

    return license_data


def find_pre_defined_file_common(layers, target_path):
    ret = []

    meta_emlinux_file = None
    for layer in layers:
        layer_name = os.path.basename(layer)
        filepath = Path(f"{layer}/{target_path}")
        if os.path.exists(filepath):
            if layer_name == "meta-emlinux":
                meta_emlinux_file = filepath.absolute()
            else:
                ret.append(filepath.absolute())

    # meta-emlinux layer is always first
    if meta_emlinux_file:
        ret.insert(0, meta_emlinux_file)
    return ret


def find_pre_defined_license_mapping_files(layers):
    return find_pre_defined_file_common(layers, "conf/licenses/license-mapping.yml")


def find_pre_defined_licenses_files(layers):
    return find_pre_defined_file_common(layers, "conf/licenses/licenses.yml")


def read_pre_defined_license_files(files):
    license_data = {}
    for filepath in files:
        license_data.update(make_user_defined_license_data(filepath))

    return license_data


def read_user_defined_license_file(user_defined_license_files):
    license_data = {}
    if user_defined_license_files:
        tmp = make_user_defined_license_data(user_defined_license_files)
        license_data.update(tmp)

    return license_data


def read_pre_defined_license_mapping_file(files):
    license_data = {}
    for filepath in files:
        with open(filepath) as f:
            license_data.update(yaml.safe_load(f))

    return license_data


def read_user_defined_license_mapping_file(user_defined_license_mapping):
    license_data = {}

    if user_defined_license_mapping:
        with open(user_defined_license_mapping, "r") as f:
            tmp = yaml.safe_load(f)
            if tmp:
                license_data.update(tmp)
    return license_data


def read_license_files(layers, user_defined_license_file):
    license_data = {}
    files = find_pre_defined_licenses_files(layers)
    license_data.update(read_pre_defined_license_files(files))
    license_data.update(read_user_defined_license_file(user_defined_license_file))

    return license_data


def read_license_mapping_files(layers, user_defined_license_mapping_file):
    license_data = {}
    files = find_pre_defined_license_mapping_files(layers)
    license_data.update(read_pre_defined_license_mapping_file(files))
    license_data.update(
        read_user_defined_license_mapping_file(user_defined_license_mapping_file)
    )
    return license_data


def write_sbom_json(output_filepath, sbom_data):
    with open(output_filepath, "w") as f:
        json.dump(sbom_data, f, indent=4, sort_keys=True)


def create_license_data(installed_pkgs, license_mapping):
    for pkg in installed_pkgs:
        logger.debug(f"Create data for {pkg}")
        licenses = installed_pkgs[pkg]["licenses"]
        installed_pkgs[pkg]["normalized_licenses"] = []

        for synopsis in installed_pkgs[pkg]["licenses"]["synopsis"]:
            license_data = licensing.debian_synopsis_to_spdx_license_id(
                pkg, synopsis, licenses.get("text"), license_mapping
            )
            # do not append duplicated data.
            if not license_data in installed_pkgs[pkg]["normalized_licenses"]:
                installed_pkgs[pkg]["normalized_licenses"].append(license_data)

        # licenses is no longer needed.
        del installed_pkgs[pkg]["licenses"]
        license_id_text = licensing.create_single_line_license_id_text(
            installed_pkgs[pkg]["normalized_licenses"]
        )
        installed_pkgs[pkg]["license_id_text"] = license_id_text


def split_license_for_imager_bom_pkgs(licenses):
    return licenses 

def create_license_data_for_imager_bom(imager_bom_pkgs, license_mapping):
    for pkg in imager_bom_pkgs:
        licenses = split_license_for_imager_bom_pkgs(imager_bom_pkgs[pkg]["license"])
        normalized_text = normalize_licese_field(licenses, license_mapping)
        imager_bom_pkgs[pkg]["normalized_license"] = normalized_text
        synopsis = parse_to_license_array(normalized_text)

        imager_bom_pkgs[pkg]["licenses"] = {
            "synopsis": synopsis,
            "text": {},
        }
        del imager_bom_pkgs[pkg]["license"]

def convert_source_info_to_package_data(pkgname, data):
    d = {}

    package = pkgname
    try:
        idx = data["provides"].index(pkgname)
        package = data["provides"][idx]
    except:
        pass

    d["package"] = package
    d["source"] = data["source_package_name"]
    d["version"] = data["version"]
    d["maintainer"] = data["maintainer"]
    d["section"] = data["section"]
    d["homepage"] = data["homepage"]
    d["arch"] = data["arch"]
    d["source"] = pkgname
    d["description"] = data["description"]
    d["license"] = data["license"]

    return d

def get_image_bom_pkg_info(imager_bom, srcinfo_json):
    srcinfo = {}
    with open(srcinfo_json) as f:
        srcinfo = json.load(f)

    srcinfo_pkgs = set([k for k in srcinfo.keys()])
    imager_bom_pkgs = set(imager_bom.strip().split(" "))

    pkg_names = imager_bom_pkgs & srcinfo_pkgs

    pkgs = {}
    for name in pkg_names:
        pkgs[name] = convert_source_info_to_package_data(name, srcinfo[name])

    return pkgs


def main(args):
    if args.verbose_output:
        logger.setLevel(logging.DEBUG)

    bitbakeinfo = bitbake_runner.get_bitbake_information(args.image)
    rootfs = bitbakeinfo["rootfs_dir"]
    dpkg_status = bitbakeinfo["dpkg_status"]

    imager_bom = bitbakeinfo["imager_bom"]

    distro = args.distro
    if not distro:
        distro = bitbakeinfo["image_distro"].split("-")[1]

    installed_pkgs = parse_dpkg_status(dpkg_status)

    layers = bitbake_runner.find_layers()
    user_defined_licenses = read_license_files(layers, args.user_defined_licenses)
    license_mapping = read_license_mapping_files(
        layers, args.user_defined_license_mapping
    )

    srcinfo_json = f"{bitbakeinfo['deploy_dir']}/images/{bitbakeinfo['machine']}/all-source-info.json"
    imager_bom_pkgs = get_image_bom_pkg_info(imager_bom, srcinfo_json)

    create_license_data_for_imager_bom(imager_bom_pkgs, license_mapping)

    packages_info = get_package_info_from_control(
        bitbakeinfo["dl_dir"],
        bitbakeinfo["repo_isar_dir"],
        distro,
        bitbakeinfo["image_distro"],
        bitbakeinfo["distro_arch"],
    )

    installed_pkgs = merge_package_data(installed_pkgs, packages_info)

    installed_pkgs.update(imager_bom_pkgs)

    read_copyright_files(rootfs, installed_pkgs, user_defined_licenses)

    create_license_data(installed_pkgs, license_mapping)

    output_dir = f"{bitbakeinfo['deploy_dir']}/sbom/{bitbakeinfo['image_full_name']}"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    output_filepath = f"{output_dir}/{args.image}-{args.sbom_format}.json"

    sbom_data = None

    logger.info(f"Create {args.sbom_format} format sbom for {args.image}")

    if args.sbom_format == "cyclonedx":
        sbom_data = sbom_cyclonedx.create_cyclonedx_sbom(
            args.product,
            args.image,
            distro,
            installed_pkgs,
            args.supplier,
            license_mapping,
        )
    else:
        sbom_data = sbom_spdx.create_spdx_sbom(
            args.product, args.image, distro, installed_pkgs, args.supplier
        )

    if sbom_data:
        write_sbom_json(output_filepath, sbom_data)
        logger.info(f"sbom was created to {output_filepath}")
    else:
        logger.critical("Failed to create SBOM.")


def parse_options():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--image",
        dest="image",
        help="EMLinux image name",
        metavar="IMAGENAME",
        required=True,
    )
    parser.add_argument(
        "--sbom-format",
        dest="sbom_format",
        help="spdx or cyclonedx",
        metavar="SBOM_FORMAT",
        required=True,
    )
    parser.add_argument(
        "--distro",
        dest="distro",
        help="debian distro name(e.g. bookworm)",
        metavar="DISTRO",
    )
    parser.add_argument(
        "--licenses",
        dest="user_defined_licenses",
        help="license yaml file",
        metavar="FILE",
    )
    parser.add_argument(
        "--license-mapping",
        dest="user_defined_license_mapping",
        help="license mapping yaml file",
        metavar="FILE",
    )
    parser.add_argument(
        "--supplier",
        dest="supplier",
        help="Supplier name(e.g. company name)",
        metavar="SUPPLIER",
        required=True,
    )
    parser.add_argument(
        "--product",
        dest="product",
        help="Product name",
        metavar="PRODUCT",
        required=True,
    )
    parser.add_argument(
        "--verbose",
        dest="verbose_output",
        help="Enable verbose output",
        action="store_true",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main(parse_options())
