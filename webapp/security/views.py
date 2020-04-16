# Standard library
from collections import OrderedDict
from datetime import datetime
from math import ceil

# Packages
import flask
from feedgen.entry import FeedEntry
from feedgen.feed import FeedGenerator
from marshmallow import EXCLUDE
from marshmallow.exceptions import ValidationError
from mistune import Markdown
from sqlalchemy import asc, desc, exc
from sqlalchemy.orm.exc import NoResultFound

# Local
from webapp.security.database import db_session
from webapp.security.models import (
    Notice,
    Reference,
    Release,
    CVE,
    Package,
    PackageReleaseStatus,
    CVEReference,
    Bug,
)
from webapp.security.schemas import NoticeSchema

markdown_parser = Markdown(
    hard_wrap=True, parse_block_html=True, parse_inline_html=True
)


def notice(notice_id):
    notice = db_session.query(Notice).get(notice_id)

    if not notice:
        flask.abort(404)

    notice_packages = set()
    releases_packages = {}

    for release, packages in notice.packages.items():
        release_name = (
            db_session.query(Release)
            .filter(Release.codename == release)
            .one()
            .version
        )
        releases_packages[release_name] = []
        for name, package in packages.get("sources", {}).items():
            # Build pacakges per release dict
            package["name"] = name
            releases_packages[release_name].append(package)
            # Build full package list
            description = package.get("description")
            package_name = f"{name} - {description}" if description else name
            notice_packages.add(package_name)

    # Guarantee release order
    releases_packages = OrderedDict(
        sorted(releases_packages.items(), reverse=True)
    )

    notice = {
        "id": notice.id,
        "title": notice.title,
        "published": notice.published,
        "summary": notice.summary,
        "isummary": notice.isummary,
        "details": markdown_parser(notice.details),
        "instructions": markdown_parser(notice.instructions),
        "packages": notice_packages,
        "releases_packages": releases_packages,
        "releases": notice.releases,
        "cves": notice.cves,
        "references": notice.references,
    }

    return flask.render_template("security/notice.html", notice=notice)


def notices():
    page = flask.request.args.get("page", default=1, type=int)
    details = flask.request.args.get("details", type=str)
    release = flask.request.args.get("release", type=str)
    order_by = flask.request.args.get("order", type=str)

    releases = db_session.query(Release).all()
    notices_query = db_session.query(Notice)

    if release:
        notices_query = notices_query.join(Release, Notice.releases).filter(
            Release.codename == release
        )

    if details:
        notices_query = notices_query.filter(
            Notice.details.ilike(f"%{details}%")
        )

    # Snapshot total results for search
    page_size = 10
    total_results = notices_query.count()
    total_pages = ceil(total_results / page_size)
    offset = page * page_size - page_size

    if page < 1 or 1 < page > total_pages:
        flask.abort(404)

    sort = asc if order_by == "oldest" else desc
    notices = (
        notices_query.order_by(sort(Notice.published))
        .offset(offset)
        .limit(page_size)
        .all()
    )

    return flask.render_template(
        "security/notices.html",
        notices=notices,
        releases=releases,
        pagination=dict(
            current_page=page,
            total_pages=total_pages,
            total_results=total_results,
            page_first_result=offset + 1,
            page_last_result=offset + len(notices),
        ),
    )


# USN Feeds
# ===


def notices_feed(feed_type):
    if feed_type not in ["atom", "rss"]:
        flask.abort(404)

    url_root = flask.request.url_root
    base_url = flask.request.base_url

    feed = FeedGenerator()
    feed.generator("Feedgen")

    feed.id(url_root)
    feed.copyright(
        f"{datetime.now().year} Canonical Ltd. "
        "Ubuntu and Canonical are registered trademarks of Canonical Ltd."
    )
    feed.title("Ubuntu security notices")
    feed.description("Recent content on Ubuntu security notices")
    feed.link(href=base_url, rel="self")

    def feed_entry(notice, url_root):
        _id = f"USN-{notice.id}"
        title = f"{_id}: {notice.title}"
        description = notice.details
        published = notice.published
        notice_path = flask.url_for(".notice", notice_id=notice.id).lstrip("/")
        link = f"{url_root}{notice_path}"

        entry = FeedEntry()
        entry.id(link)
        entry.title(title)
        entry.description(description)
        entry.link(href=link)
        entry.published(f"{published} UTC")
        entry.author(dict(name="Ubuntu Security Team"))

        return entry

    notices = (
        db_session.query(Notice)
        .order_by(desc(Notice.published))
        .limit(10)
        .all()
    )

    for notice in notices:
        feed.add_entry(feed_entry(notice, url_root), order="append")

    payload = feed.atom_str() if feed_type == "atom" else feed.rss_str()
    return flask.Response(payload, mimetype="text/xml")


# USN API
# ===


def api_create_notice():
    # Because we get a dict with ID as a key and the payload as a value
    notice_id, payload = flask.request.json.popitem()

    notice = db_session.query(Notice).filter(Notice.id == notice_id).first()
    if notice:
        return (
            flask.jsonify({"message": f"Notice '{notice.id}' already exists"}),
            400,
        )

    notice_schema = NoticeSchema()

    try:
        data = notice_schema.load(payload, unknown=EXCLUDE)
    except ValidationError as error:
        return (
            flask.jsonify(
                {"message": "Invalid payload", "errors": error.messages}
            ),
            400,
        )

    notice = Notice(
        id=data["notice_id"],
        title=data["title"],
        summary=data["summary"],
        details=data["description"],
        packages=data["releases"],
        published=datetime.fromtimestamp(data["timestamp"]),
    )

    if "action" in data:
        notice.instructions = data["action"]

    if "isummary" in data:
        notice.isummary = data["isummary"]

    # Link releases
    for release_codename in data["releases"].keys():
        try:
            notice.releases.append(
                db_session.query(Release)
                .filter(Release.codename == release_codename)
                .one()
            )
        except NoResultFound:
            message = f"No release with codename: {release_codename}."
            return (flask.jsonify({"message": message}), 400)

    # Link CVEs, creating them if they don't exist
    refs = set(data.get("references", []))
    for ref in refs:
        if ref.startswith("CVE-"):
            cve_id = ref[4:]
            cve = db_session.query(CVE).filter(CVE.id == cve_id).first()
            if not cve:
                cve = CVE(id=cve_id)
            notice.cves.append(cve)
        else:
            reference = (
                db_session.query(Reference)
                .filter(Reference.uri == ref)
                .first()
            )
            if not reference:
                reference = Reference(uri=ref)
            notice.references.append(reference)

    db_session.add(notice)
    db_session.commit()

    return flask.jsonify({"message": "Notice created"}), 201


# CVE views
# ===
def cve_index():
    """
    Display the list of CVEs, with pagination.
    Also accepts the following filtering query parameters:
    - order-by - "oldest" or "newest"
    - query - search query for the description field
    - priority
    - limit - default 20
    - offset - default 0
    """

    # Query parameters
    order_by = flask.request.args.get("order-by", default="oldest")
    query = flask.request.args.get("q")
    priority = flask.request.args.get("priority")
    package = flask.request.args.get("package")
    limit = flask.request.args.get("limit", default=20, type=int)
    offset = flask.request.args.get("offset", default=0, type=int)

    # Basic queries
    cves_query = db_session.query(CVE)
    releases_query = db_session.query(Release)

    # Apply search filters
    if package:
        cves_query = cves_query.join(Package, CVE.packages).filter(
            Package.name.ilike(f"%{package}%")
        )

    if priority:
        cves_query = cves_query.filter(CVE.priority == priority)

    if query:
        cves_query = cves_query.filter(CVE.description.ilike(f"%{query}%"))

    sort = asc if order_by == "oldest" else desc

    cves = (
        cves_query.order_by(sort(CVE.public_date))
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Pagination
    total_results = cves_query.count()

    return flask.render_template(
        "security/cve/index.html",
        releases=releases_query.all(),
        cves=cves,
        total_results=total_results,
        total_pages=ceil(total_results / limit),
        offset=offset,
        limit=limit,
        priority=priority,
        query=query,
    )


def cve(cve_id):
    """
    Retrieve and display an individual CVE details page
    """

    cve = db_session.query(CVE).get(cve_id.upper())
    if not cve:
        flask.abort(404)
    return flask.render_template("security/cve/cve.html", cve=cve)


# CVE API
# ===


def create_cve():
    """
    Receives a POST request from load_cve.py
    Parses the object and bulk inserts with add_all()
    @params json: the body of the request
    """

    data = flask.request.get_json()
    response = flask.jsonify({"message": "Unable to get body"}), 400
    packages = []
    references = []
    bugs = []

    # Check if CVE exists by candidate
    if db_session.query(CVE).filter(CVE.id == data["id"]).count() > 0:
        response = flask.jsonify({"message": "CVE already exists"}), 400
        return response

    # Packages
    # Check if there are packages before mapping
    if "packages" in data and len(data["packages"]) > 0:
        for pkg in data["packages"]:
            releases = []
            for rel in pkg["releases"]:
                release = PackageReleaseStatus(
                    name=rel["name"],
                    status=rel["status"],
                    status_description=rel["status_description"],
                )
            releases.append(release)
            package = Package(
                name=pkg["name"],
                source=pkg["source"],
                ubuntu=pkg["ubuntu"],
                debian=pkg["debian"],
                releases=releases,
            )
            packages.append(package)

    if "references" in data and len(data["references"]) > 0:
        for ref in data["references"]:
            reference = CVEReference(uri=ref)
            references.append(reference)

    if "bugs" in data and len(data["bugs"]) > 0:
        for b in data["bugs"]:
            bug = Bug(uri=b)
            bugs.append(bug)

    cves = [
        CVE(
            id=data["id"],
            status=data["status"] if "status" in data else "",
            last_updated_date=data["last_updated_date"]
            if "last_updated_date" in data
            else None,
            public_date_usn=data["public_date_usn"]
            if "public_date_usn" in data
            else None,
            priority=data["priority"] if "priority" in data else None,
            cvss=data["cvss"] if "cvss" in data else "",
            assigned_to=data["assigned_to"] if "assigned_to" in data else "",
            discovered_by=data["discovered_by"]
            if "discovered_by" in data
            else "",
            approved_by=data["approved_by"] if "approved_by" in data else "",
            description=data["description"] if "description" in data else "",
            ubuntu_description=data["ubuntu_description"]
            if "ubuntu_description" in data
            else "",
            notes=data["notes"] if "notes" in data else "[]",
            packages=packages,
            references=references,
            bugs=bugs,
        )
    ]

    try:
        db_session.add_all(cves)
        db_session.commit()
    except exc.SQLAlchemyError as e:
        response = flask.jsonify({"message": e}), 400
        return response

    response = flask.jsonify({"message": "CVE created succesfully"}), 200
    return response


def update_cve():
    data = flask.request.json
    response = flask.jsonify({"message": "Unable to get body"}), 400
    cve = db_session.query(CVE).filter(CVE.id == data["id"]).first()

    # Check if CVE exists by candidate
    if len(db_session.query(CVE).all()) == 0:
        response = flask.jsonify({"message": "CVE does not exist"}), 400
        return response

    cve.status = data["status"]
    cve.last_updated_date = data["last_updated_date"]
    cve.public_date_usn = data["public_date_usn"]
    cve.public_date = data["public_date"]
    cve.priority = data["priority"]
    cve.crd = data["crd"]
    cve.cvss = data["cvss"]
    cve.assigned_to = data["assigned_to"]
    cve.discovered_by = data["discovered_by"]
    cve.approved_by = data["approved_by"]
    cve.description = data["description"]
    cve.ubuntu_description = data["ubuntu_description"]
    cve.notes = data["notes"]
    cve.packages.clear()
    cve.references.clear()
    cve.bugs.clear()

    if "references" in data and len(data["references"]) > 0:
        for uri in data["references"]:
            reference = (
                db_session.query(CVEReference)
                .filter(CVEReference.uri == uri)
                .first()
            )
            if not reference:
                reference = CVEReference(uri=uri)
            cve.references.append(reference)

    if "bugs" in data and len(data["bugs"]) > 0:
        for b in data["bugs"]:
            bug = db_session.query(Bug).filter(Bug.uri == uri).first()
            if not bug:
                bug = Bug(uri=b)
            cve.bugs.append(bug)

    # Packages
    # Check if there are packages before mapping
    if len(data["packages"]) > 0:
        for pkg in data["packages"]:
            package = (
                db_session.query(Package)
                .filter(Package.name == pkg["name"])
                .first()
            )
            package.releases.clear()
            if not package:
                package = Package(
                    name="made up package",  # pkg["name"],
                    source=pkg["source"],
                    ubuntu=pkg["ubuntu"],
                    debian=pkg["debian"],
                    releases=[],
                )
            for rel in pkg["releases"]:
                package_release_status = (
                    db_session.query(CVEReference)
                    .filter(CVEReference.uri == uri)
                    .first()
                )
                if not package_release_status:
                    package_release_status = PackageReleaseStatus(
                        name=rel["name"],
                        status=rel["status"],
                        status_description=rel["status_description"],
                    )

                package.releases.append(package_release_status)
            cve.packages.append(package)

    try:
        # Bulk function, add() for single
        db_session.add(cve)
        db_session.commit()
    except exc.SQLAlchemyError as e:
        print(e)
        response = (
            flask.jsonify({"message": e}),
            400,
        )

    response = flask.jsonify({"message": "CVE updated succesfully"}), 200
    return response


def delete_cve(cve_id):
    """
    Delete a CVE from db
    @params string: query string with the CVE id
    """
    response = flask.jsonify({"message": "Unable to get body"}), 400
    cve_query = db_session.query(CVE)
    cve = cve_query.filter(CVE.id == cve_id).first()

    # Check if CVE exists
    if cve_query.filter(CVE.id == cve_id).count() == 0:
        response = flask.jsonify({"message": "CVE does not exist"}), 400
        return response

    try:
        db_session.delete(cve)
        db_session.commit()
    except exc.SQLAlchemyError as e:
        response = flask.jsonify({"message": e}), 400
        return response

    response = flask.jsonify({"message": "CVE deleted succesfully"}), 200
    return response
