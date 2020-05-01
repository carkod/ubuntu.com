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
from sqlalchemy import asc, desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

# Local
from webapp.security.database import db_session
from webapp.security.models import (
    Notice,
    Reference,
    Release,
    CVE,
)
from webapp.security.schemas import NoticeSchema
from webapp.security.auth import authorization_required

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

    releases = (
        db_session.query(Release).order_by(desc(Release.release_date)).all()
    )
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


@authorization_required
def create_notice():
    if not flask.request.json:
        return (flask.jsonify({"message": f"No payload received"}), 400)

    notice_schema = NoticeSchema()
    try:
        data = notice_schema.load(flask.request.json, unknown=EXCLUDE)
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
            cve = db_session.query(CVE).get(cve_id)
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

    try:
        db_session.add(notice)
        db_session.commit()
    except IntegrityError:
        return (
            flask.jsonify({"message": f"Notice '{notice.id}' already exists"}),
            400,
        )

    return flask.jsonify({"message": "Notice created"}), 201


# CVE views
# ===
def cve_index():
    return flask.render_template("security/cve/index.html")


def cve(cve_id):
    return flask.render_template("security/cve/cve.html")


# CVE API
# ===
