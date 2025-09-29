#!/usr/bin/python3

#
# EMLinux CVE checker
#
# Copyright (c) Cybertrust Japan Co., Ltd.
#
# SPDX-License-Identifier: MIT
#

from lib.python.cve.plugin.eml_cve_plugin_base import EmlCvePlugin
import lib.python.cve.lib as lib
from lib.python.cve.nvd_lib import CveCheckMergedList, NvdCveInfoListCreator
from lib.python.cve.cve_reporter import CveReporter
from lib.python.package_info import PackageInfo, PackageInfoList, PackageInfoHelper, PackageMap
from lib.python.cve.cve_product import CveProduct, CveProductList
from lib.python.cve.cve_info import CveStatus, CveCheckResult, CveCheckResultList
from lib.python.cve.kev_info import KevInfoList
import lib.python.cve.kev_cve as kev_cve

import argparse
import sys
import os, os.path
import yaml
import debian.debian_support
from typing import Any
import traceback

import logging
logging.basicConfig(level = logging.INFO, format='%(asctime)s:%(levelname)s: %(message)s')
logger = logging.getLogger("emlinux-cve-check")

sys.path.append(os.path.join(os.path.dirname(__file__), 'lib/python'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib/python/cve'))

import bitbake_runner
import json
import glob

import importlib.util
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import pprint

def create_ignore_list(extra_cve_check_ignore: str) -> Any:
    name = os.path.join(os.path.dirname(__file__), "../conf/cve/cve_check_ignore.yml")

    data = None
    with open(name, "r") as f:
        data = yaml.safe_load(f)

    if extra_cve_check_ignore:
        with open(extra_cve_check_ignore, "r") as f:
            tmp = yaml.safe_load(f)
            if tmp:
                if data is None:
                    data = {}
                for pkg in tmp:
                    if pkg in data:
                        data[pkg] = data[pkg] + tmp[pkg]
                    else:
                        data[pkg] = tmp[pkg]

    return data

def create_cve_check_merged_list(src_pkg_names: list[str], check_results: Any) -> CveCheckMergedList:
    cve_check_merged_list = CveCheckMergedList()

    cve_ids = create_cve_id_list_by_src_pkg_name_from_check_result(src_pkg_names, check_results)
    for src_pkg_name in src_pkg_names:
        for cveid in cve_ids:
            for cr in check_results:
                vulns = cr[src_pkg_name]
                if vulns is None:
                    # Plugin doesn't have CVE information for the src_pkg_name
                    continue
                if cveid in vulns:
                    cve_check_merged_list.add_data(src_pkg_name, cveid, vulns[cveid], cr.priority)
                else:
                    # Plugin doesn't have CVE information for the CVE
                    pass
                    #logger.debug(f"{cveid} {src_pkg_name} is not found")
    return cve_check_merged_list

def create_cve_id_list_by_src_pkg_name_from_check_result(src_pkg_names: list[str], check_results: Any) -> list[str]:
    tmp_cve_ids = []
    for src_pkg_name in src_pkg_names:
        for cr in check_results:
            ci = cr.cve_ids_by_src_pkg(src_pkg_name)
            if ci:
                tmp_cve_ids.extend(ci)
    return list(dict.fromkeys(tmp_cve_ids))

# make a source package name list which content has CVE information
def create_src_package_name_list_from_check_result(check_results: Any) -> list[str]:
    tmp_list = []
    for result in check_results:
        tmp_list.extend(result.src_pkg_names())
    return list(dict.fromkeys(tmp_list))

def read_recipe_source_info(deploy_dir: str) -> Any:
    filepath = deploy_dir + "/all-source-info.json"
    return lib.read_json(filepath)

def load_plugin(plugin_file: str) -> EmlCvePlugin:
    path = pathlib.Path(plugin_file).resolve()
    if not path.exists():
        logger.error(f"Failed to find plugin {plugin_file}")
        exit(1)

    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    if not spec or not spec.loader:
        logger.error(f"Fail to load spec from {plugin_file}")
        exit(1)

    mod = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        logger.error(e)
        traceback.print_exc()
        exit(1)

    for obj in vars(mod).values():
        if isinstance(obj, type) and issubclass(obj, EmlCvePlugin) and obj is not EmlCvePlugin:
            return obj

    logger.info(f"Plugin is not found in {plugin_file}")

    return None

def load_plugins(plugin_files: list[str]):
    plugins = []

    for plugin_file in plugin_files:
        logger.debug(f"loading {plugin_file}")
        obj = load_plugin(plugin_file)
        if obj:
            plugins.append(obj)

    return plugins

def find_plugins() -> list[str]:
    layer_dirs = bitbake_runner.find_layers()
    plugins = []

    plugin_dir = "/scripts/lib/python/cve/plugin/"
    for ld in layer_dirs:
        d = ld + plugin_dir
        pattern = f"{d}/eml_cve_*_plugin.py"
        for plugin in glob.glob(pattern):
            plugins.append(plugin)

    return plugins

def cve_check_worker(plugin: EmlCvePlugin, args: Any):
    logger.debug(f"run {plugin.plugin_name}")

    if not args.skip_update:
        ret = plugin.update_database()
        if not ret:
            raise Exception(f"{plugin.plugin_name}: Failed to update datebase")

    if args.update_cve_databese_only:
        return {}

    return plugin.run_check()

def fetch_kev_data(cve_data_dir: str) -> KevInfoList:
    try:
        kev_json = kev_cve.fetch_kev_data(cve_data_dir)
        return KevInfoList(lib.read_json(kev_json))
    except:
        return KevInfoList({})

def main(args: dict):
    if args.verbose_output:
       logger.setLevel(logging.DEBUG)

    bitbakeinfo = bitbake_runner.get_bitbake_information(args.image_name)

    dpkg_status_file = bitbakeinfo["dpkg_status"] if not args.dpkg_status_file else args.dpkg_status_file
    installed_packages = PackageInfoHelper.parse_dpkg_status_file(dpkg_status_file, target_source_package=args.target_source_package)
    recipe_source_info = read_recipe_source_info(bitbakeinfo["deploy_image_dir"])
    
    installed_packages.merge_recipe_source_info(recipe_source_info)

    cve_product_list = CveProductList()
    cve_product_list.read_cve_products_file(args.extra_cve_product)

    cve_data_dir = f"{bitbakeinfo['dl_dir']}/CVE"
    lib.create_directory(cve_data_dir)

    installed_packages.merge_cve_product_list(cve_product_list)

    package_name_map = PackageInfoHelper.create_bin_src_package_name_map(installed_packages)
     
    plugin_files = find_plugins()
    plugin_objs = load_plugins(plugin_files)

    plugins = []
    for obj in plugin_objs:
        o = obj(cve_data_dir, args, bitbakeinfo, installed_packages)
        plugins.append(o)

    check_results = []
    max_workers = min(args.threads, len(plugins))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(cve_check_worker, p, args) for p in plugins]
            for f in as_completed(futures):
                try:
                    check_results.append(f.result())
                except Exception as e:
                    logger.error(f"error: {e}")
                    traceback.print_exc()
                    exit(1)

    if args.update_cve_databese_only:
        logger.info("Updating database finished.") 
        exit(0)

    # sort by plugin priority
    check_results = sorted(check_results, key=lambda d: d.priority)

    src_pkg_names = create_src_package_name_list_from_check_result(check_results)

    cve_check_merged_list = create_cve_check_merged_list(src_pkg_names, check_results)

    ignore_list = create_ignore_list(args.extra_cve_check_ignore)
    cve_check_merged_list.apply_ignore_list_info(ignore_list)

    kev_info_list = fetch_kev_data(cve_data_dir)

    creator = NvdCveInfoListCreator(cve_data_dir, package_name_map, kev_info_list)
    creator.create_cve_info_list(cve_check_merged_list)

    cve_info_list = creator.get_nvd_info_list()

    output_base_dir = f"{bitbakeinfo['deploy_dir']}/cve/{bitbakeinfo['image_full_name']}"
    # Use cve_check_ng scripts own directory for testing
    output_base_dir = f"{output_base_dir}/cve_check_ng"

    reporter = CveReporter(output_base_dir, bitbakeinfo["image_full_name"], package_name_map)
    reporter.write_report(args.output_format, cve_info_list, installed_packages)

def parse_options():
    parser = argparse.ArgumentParser()

    parser.add_argument("--nvd-api-key", dest="nvd_api_key", help="API key for NVD API",
            metavar="NVDAPIKEY")
    parser.add_argument("--debian-codename", dest="debian_codename", help="debian codename(Debian 12 is bookworm)",
            default="bookworm", metavar="DEBIANCODENAME")
    parser.add_argument("--output-format", dest="output_format", help="output format. available formats are text, json. formats can be comma separated string(e.g. text,json)",
            default="text", metavar="OUTPUTFORMAT")
    parser.add_argument("--cve-product", dest="extra_cve_product", help="User defined cve-product file",
            metavar="CVEPRODUCT")
    parser.add_argument("--cve-ignore", dest="extra_cve_check_ignore", help="User defined cve-check-ignore file",
            metavar="CVEPRODUCT")
    parser.add_argument("--image-name", dest="image_name", help="EMLinux image name",
            metavar="IMAGENAME", required=True)
    parser.add_argument("--cve-db-predownload", dest="cve_db_predownload", action="store_true", help="Enable CVE database predownload.URL should be defined by CVE_DB_PREDOWNLOAD_URL in conf/local.conf.")
    parser.add_argument("--update-cve-databese-only", dest="update_cve_databese_only", default=False, action="store_true",
            help="Do not run cve check. Update CVE database only.")
    parser.add_argument("--verbose", dest="verbose_output", help="Enable verbose output",
            default=False, action="store_true")
    parser.add_argument("--threads", default=1, help="Number of thread for cve check")
    parser.add_argument("--skip-update", default=False, action="store_true")
    parser.add_argument("--target-source-package", dest="target_source_package",  help="Only check given debian source package", metavar="DEBIAN SOURCE PACKAGE NAME")
    parser.add_argument("--dpkg-status-file", dest="dpkg_status_file",  help="Use specific dpkg_status file instead of default", metavar="DPKG STATUS FILE")

    return parser.parse_args()

if __name__ == "__main__":
    logger.info("|------------------------------|")
    logger.info("| This is experimental version |")
    logger.info("|------------------------------|")
    main(parse_options())
