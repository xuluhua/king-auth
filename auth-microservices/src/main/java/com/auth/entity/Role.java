package com.auth.entity;

import java.io.Serializable;
import java.util.UUID;

public class Role implements Serializable {
	private UUID id;

	private String rolename;

	public UUID getId() {
		return id;
	}

	public void setId(UUID id) {
		this.id = id;
	}

	public String getRolename() {
		return rolename;
	}

	public void setRolename(String rolename) {
		this.rolename = rolename;
	}
}
