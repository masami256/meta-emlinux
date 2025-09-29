from typing import Any
from lib.python.cve.cve_product import CveProduct, CveProductList
from lib.python.cve.cve_info import CveCheckResultList
from lib.python.package_info import PackageInfoList, PackageInfoHelper, PackageInfo

class EmlCvePlugin:
    def __init__(self, plugin_name: str, priority: int, cve_data_dir: str, args: Any, bitbakeinfo: Any, installed_packages: PackageInfoList):
        self.plugin_name = plugin_name
        self.plugin_priority = priority
        self.cve_data_dir = cve_data_dir
        self.args = args
        self.bitbakeinfo = bitbakeinfo
        self.installed_packages = installed_packages
        self.cve_check_result_list = CveCheckResultList(self.plugin_name, self.plugin_priority)

    def update_database(self) -> bool:
        raise NotImplementedError("It must be implemented in your plugin module")

    def run_check(self) -> CveCheckResultList:
        raise NotImplementedError("It must be implemented in your plugin module")

    def _get_cve_products_from_source_package_name(self, src_pkg_name: str) -> CveProduct:
        return PackageInfoHelper.get_cve_product_by_source_pkg_name(self.installed_packages, src_pkg_name)
