from typing import Any

import httpx


class CloudflareError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None, payload: Any | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class CloudflareClient:
    def __init__(self, token: str, base_url: str = "https://api.cloudflare.com/client/v4"):
        self.token = token
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"
        headers["Content-Type"] = "application/json"
        url = f"{self.base_url}{path}"
        with httpx.Client(timeout=20) as client:
            response = client.request(method, url, headers=headers, **kwargs)
        try:
            payload = response.json()
        except ValueError:
            payload = {"success": False, "errors": [{"message": response.text}]}
        if response.status_code >= 400 or not payload.get("success", False):
            errors = payload.get("errors") or []
            message = "; ".join(error.get("message", str(error)) for error in errors) or response.text
            raise CloudflareError(message, response.status_code, payload)
        return payload

    def _paginated(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        params = dict(params or {})
        page = 1
        results: list[dict[str, Any]] = []
        while True:
            params.update({"page": page, "per_page": 100})
            payload = self._request("GET", path, params=params)
            results.extend(payload.get("result", []))
            info = payload.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages:
                break
            page += 1
        return results

    def list_zones(self) -> list[dict[str, Any]]:
        return self._paginated("/zones")

    def list_dns_records(self, zone_id: str, name: str | None = None) -> list[dict[str, Any]]:
        params = {}
        if name:
            params["name"] = name
        return self._paginated(f"/zones/{zone_id}/dns_records", params=params)

    def create_dns_record(self, zone_id: str, record: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", f"/zones/{zone_id}/dns_records", json=record)["result"]

    def update_dns_record(self, zone_id: str, record_id: str, record: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", json=record)["result"]

    def patch_dns_record(self, zone_id: str, record_id: str, record: dict[str, Any]) -> dict[str, Any]:
        return self._request("PATCH", f"/zones/{zone_id}/dns_records/{record_id}", json=record)["result"]

    def delete_dns_record(self, zone_id: str, record_id: str) -> None:
        self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

