// mlbInjector.h

#pragma once

using namespace System;

namespace mlbInjector {

	public ref class Injector
	{
    public: static bool Inject(DWORD processID);
	};
}
