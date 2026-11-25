def test_device_security_event_page_size_contract():
    from backend.app.persistence.device_security_events import DeviceSecurityEventRepository

    try:
        DeviceSecurityEventRepository.list_owned(None, "owner", limit=101)
    except ValueError as exc:
        assert "between 1 and 100" in str(exc)
    else:
        raise AssertionError("unbounded page size accepted")
