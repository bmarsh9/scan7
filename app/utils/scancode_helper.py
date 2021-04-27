from flask import current_app
from scancode import cli
from app.models import *

class ScHelper():
    def __init__(self,repo=None,scan=None,save_to_db=False):
        '''
        repo: <Repository> object
        scan: <RepositoryScan> object
        save_to_db: if the scan is successful, save to database

        Examples:

            ScHelper(<repo>,<scan>,save_to_db=True).scan("/location/of/file_or_dir")
        '''
        self.repo = repo
        self.scan = scan
        self.save_to_db = save_to_db

        self.success = False

    def run_scan(self,location):
        '''
        location: path to start the scan
        '''
        success, _results = cli.run_scan(
            location,
            quiet=True,
            license=True,
            copyright=True,
            url=True,
            package=True,
            info=True,
            email=True,
            classify=True,
            list_packages=True,
            return_results=True
        )
        self.success = success
        if success and self.save_to_db:
            self.insert_data_to_db(_results)
        return self.success, _results

    def insert_data_to_db(self,_results):
        if not self.repo:
            raise ValueError("invalid or empty Repostitory object. See repo_id argument")
        if not self.scan:
            raise ValueError("invalid or empty RepostitoryScan object. See scan_id argument")

        rel_keys = ['licenses', 'license_expressions', 'copyrights', 'holders',
            'authors', 'packages', 'emails', 'urls', 'scan_errors']
        base_keys = ['path', 'type', 'name', 'base_name', 'extension',
            'size', 'date', 'sha1', 'md5', 'sha256', 'mime_type',
            'file_type', 'programming_language', 'is_binary', 'is_text',
            'is_archive', 'is_media', 'is_source', 'is_script', 'percentage_of_license_text',
            'is_legal', 'is_manifest', 'is_readme', 'is_top_level', 'is_key_file',
            'files_count', 'dirs_count', 'size_count']

        duration = _results["headers"][0]["duration"]
        errors = _results["headers"][0]["errors"]
        message = _results["headers"][0]["message"]
        file_count = _results["headers"][0]["extra_data"]["files_count"]

        for scanned_file in _results["files"]:
            file = File()
            for key,value in scanned_file.items():
                if key in base_keys: # all keys w.o relationship
                    setattr(file,key,value)
                elif key == "licenses":
                    for license in value:
                        license["repo_id"] = self.repo.id
                        license["repo_name"] = self.repo.name
                        license["scan_id"] = self.scan.id
                        file.licenses.append(FileLicense(**license))
                elif key == "license_expressions":
                    for expression in value:
                        file.license_expressions.append(FileLicenseExpression(value=expression,
                            repo_id=self.repo.id,repo_name=self.repo.name,scan_id=self.scan.id))
                elif key == "copyrights":
                    for copyright in value:
                        copyright["repo_id"] = self.repo.id
                        copyright["repo_name"] = self.repo.name
                        copyright["scan_id"] = self.scan.id
                        file.copyrights.append(FileCopyright(**copyright))
                elif key == "holders":
                    for holder in value:
                        holder["repo_id"] = self.repo.id
                        holder["repo_name"] = self.repo.name
                        holder["scan_id"] = self.scan.id
                        file.holders.append(FileHolder(**holder))
                elif key == "authors":
                    for author in value:
                        author["repo_id"] = self.repo.id
                        author["repo_name"] = self.repo.name
                        author["scan_id"] = self.scan.id
                        file.authors.append(FileAuthor(**author))
                elif key == "packages":
                     for pkg in value:
                         file_package = FilePackage(repo_id=self.repo.id,
                             repo_name=self.repo.name,scan_id=self.scan.id)
                         for pkg_key,pkg_value in pkg.items():
                             if pkg_key in ["dependencies"]: # foreign relationship
                                 for dependency in pkg_value:
                                     dependency["repo_id"] = self.repo.id
                                     dependency["repo_name"] = self.repo.name
                                     dependency["scan_id"] = self.scan.id
                                     pkg_dependency = PackageDependency(**dependency)
                                     file_package.dependencies.append(pkg_dependency)
                             else:
                                 setattr(file_package,pkg_key,pkg_value)
                         file.packages.append(file_package)
                elif key == "emails":
                    for email in value:
                        email["repo_id"] = self.repo.id
                        email["repo_name"] = self.repo.name
                        email["scan_id"] = self.scan.id
                        file.emails.append(FileEmail(**email))
                elif key == "urls":
                    for url in value:
                        url["repo_id"] = self.repo.id
                        url["repo_name"] = self.repo.name
                        url["scan_id"] = self.scan.id
                        file.urls.append(FileUrl(**url))
                elif key == "scan_errors":
                    file.scan_errors.append(FileScanError(errors=value,
                        repo_id=self.repo.id,repo_name=self.repo.name,
                        scan_id=self.scan.id))
            self.scan.files.append(file)

        self.repo.scans.append(self.scan)
        db.session.add(self.repo)
        db.session.commit()
        return self.success
