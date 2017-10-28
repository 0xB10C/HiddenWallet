﻿using HiddenWallet.ChaumianTumbler.Configuration;
using HiddenWallet.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HiddenWallet.ChaumianTumbler
{
	public static class Global
	{
		public static Config Config;

		public static TumblerStateMachine StateMachine;
		public static Task StateMachineJob;
		public static CancellationTokenSource StateMachineJobCancel;

		private static string _dataDir = null;
		public static string DataDir
		{
			get
			{
				if (_dataDir != null) return _dataDir;

				_dataDir = EnvironmentHelpers.GetDataDir("ChaumianTumbler");

				return _dataDir;
			}
		}
	}
}
