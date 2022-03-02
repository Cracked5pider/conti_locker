#pragma once
#include "common.h"
#include "api.h"

namespace logs {

	VOID Init();
	VOID Write(LPCWSTR Format, ...);

}