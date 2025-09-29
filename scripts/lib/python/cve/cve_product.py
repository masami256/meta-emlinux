from typing import Any
import yaml
import os

class CveProductVendorProructPair:
    def __init__(self, vendor: str, product: str):
        self.vendor = vendor
        self.product = product

    def __repr__(self) -> str:
        return f"{self.__dict__}"

class CveProduct:
    def __init__(self, src_pkg_name: str):
        self.src_pkg_name = src_pkg_name
        self.pair = None

    def set_pair_list(self, pair_list: list[CveProductVendorProructPair]):
        self.pair = pair_list

    def __repr__(self) -> str:
        return f"{self.__dict__}"

    def __iter__(self) -> CveProductVendorProructPair:
        return iter(self.pair)

class CveProductList:
    def __init__(self):
        self.cve_products = {}

    def __repr__(self) -> str:
        return f"{self.__dict__}"

    def __iter__(self) -> Any:
        return iter(self.cve_products)

    def __getitem__(self, key: str) -> CveProduct:
        return self.cve_products[key]

    def read_cve_products_file(self, extra_cve_product: str):
        name = os.path.join(os.path.dirname(__file__), "../../../../conf/cve/cve_products.yml")

        data = None
        with open(name, "r") as f:
            data = yaml.safe_load(f)

        if extra_cve_product:
            with open(extra_cve_product, "r") as f:
                tmp = yaml.safe_load(f)
                if tmp:
                    data.update(tmp)

        for pkgname in data:
            pkg = data[pkgname]
            tmp_product_list = []

            if type(pkg) == list:
                for d in pkg:
                    tmp = self._create_pair(d)
                    tmp_product_list.append(tmp)

            elif type(pkg) == dict:
                tmp = self._create_pair(pkg)
                tmp_product_list.append(tmp)

            if len(tmp_product_list) > 0:
                cveproduct = CveProduct(pkgname)
                cveproduct.set_pair_list(tmp_product_list)

                self.cve_products[pkgname] = cveproduct

    def _create_pair(self, data: dict) -> dict:
        vendor = None
        product = None

        if "product" in data:
            product = data["product"]
        if "vendor" in data:
            vendor = data["vendor"]
 
        return CveProductVendorProructPair(vendor, product)
