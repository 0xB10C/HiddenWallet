﻿using HiddenWallet.ChaumianCoinJoin;
using HiddenWallet.ChaumianTumbler.Configuration;
using HiddenWallet.ChaumianTumbler.Models;
using HiddenWallet.WebClients.SmartBit;
using NBitcoin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HiddenWallet.ChaumianTumbler
{
    public class TumblerStateMachine : IDisposable
    {
		public TumblerPhase Phase { get; private set; } = TumblerPhase.InputRegistration;
		public Money Denomination { get; private set; }
		public int AnonymitySet { get; private set; } = (int)Global.Config.MinimumAnonymitySet;
		public TimeSpan TimeSpentInInputRegistration { get; private set; } = TimeSpan.FromSeconds((int)Global.Config.AverageTimeToSpendInInputRegistrationInSeconds) + TimeSpan.FromSeconds(1); // took one sec longer, so the first round will use the same anonymity set

		private SmartBitClient SmartBitClient { get; }

		private TumblerPhaseBroadcaster _broadcaster = TumblerPhaseBroadcaster.Instance;

		private CancellationTokenSource _ctsPhaseCancel = new CancellationTokenSource();

		public TumblerStateMachine()
		{
			SmartBitClient = new SmartBitClient(Network.Main);
		}

		public void UpdatePhase(TumblerPhase phase)
		{
			if (phase == Phase) return;

			Phase = phase;
			_ctsPhaseCancel.Cancel();
			_ctsPhaseCancel = new CancellationTokenSource();
			var broadcast = new PhaseChangeBroadcast { NewPhase = phase.ToString(), Message = "" };
			_broadcaster.Broadcast(broadcast);
			Console.WriteLine($"NEW PHASE: {phase}");
		}

		public void AdvancePhase()
		{
			switch (Phase)
			{
				case TumblerPhase.InputRegistration:
					{
						UpdatePhase(TumblerPhase.InputConfirmation);
						break;
					}
				case TumblerPhase.InputConfirmation:
					{
						UpdatePhase(TumblerPhase.OutputRegistration);
						break;
					}
				case TumblerPhase.OutputRegistration:
					{
						UpdatePhase(TumblerPhase.Signing);
						break;
					}
				case TumblerPhase.Signing:
					{
						UpdatePhase(TumblerPhase.InputRegistration);
						break;
					}
				default:
					{
						throw new NotSupportedException("This should never happen");
					}
			}
		}

		public async Task StartAsync(CancellationToken cancel)
		{
			while (true)
			{
				try
				{
					if (cancel.IsCancellationRequested) return;

					switch(Phase)
					{
						case TumblerPhase.InputRegistration:
							{
								await SetDenominationAsync(cancel);
								CalculateAnonymitySet();

								Stopwatch stopwatch = new Stopwatch();
								stopwatch.Start();
								using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel, _ctsPhaseCancel.Token))
								{
									await Task.Delay(TimeSpan.FromSeconds((int)Global.Config.InputRegistrationPhaseTimeoutInSeconds), cts.Token).ContinueWith(t => { });
								}
								stopwatch.Stop();
								TimeSpentInInputRegistration = stopwatch.Elapsed;

								AdvancePhase();
								break;
							}
						case TumblerPhase.InputConfirmation:
							{
								using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel, _ctsPhaseCancel.Token))
								{
									await Task.Delay(TimeSpan.FromSeconds((int)Global.Config.InputConfirmationPhaseTimeoutInSeconds), cts.Token).ContinueWith(t => { });
								}
								AdvancePhase();
								break;
							}
						case TumblerPhase.OutputRegistration:
							{
								using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel, _ctsPhaseCancel.Token))
								{
									await Task.Delay(TimeSpan.FromSeconds((int)Global.Config.OutputRegistrationPhaseTimeoutInSeconds), cts.Token).ContinueWith(t => { });
								}
								AdvancePhase();
								break;
							}
						case TumblerPhase.Signing:
							{
								using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancel, _ctsPhaseCancel.Token))
								{
									await Task.Delay(TimeSpan.FromSeconds((int)Global.Config.SigningPhaseTimeoutInSeconds), cts.Token).ContinueWith(t => { });
								}
								AdvancePhase();
								break;
							}
						default:
							{
								throw new NotSupportedException("This should never happen");
							}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"Ignoring {nameof(TumblerStateMachine)} exception: {ex}");
				}
			}
		}

		private void CalculateAnonymitySet()
		{
			var min = (int)Global.Config.MinimumAnonymitySet;
			var max = (int)Global.Config.MaximumAnonymitySet;
			// If the previous non-fallback Input Registration phase took more than three minutes
			if (TimeSpentInInputRegistration > TimeSpan.FromSeconds((int)Global.Config.AverageTimeToSpendInInputRegistrationInSeconds))
			{
				// decrement this round's desired anonymity set relative to the previous desired anonymity set,
				AnonymitySet = Math.Max(min, AnonymitySet - 1);
			}
			else
			{
				// otherwise increment it
				AnonymitySet = Math.Min(max, AnonymitySet + 1);
			}
		}

		private async Task SetDenominationAsync(CancellationToken cancel)
		{
			if (Global.Config.DenominationAlgorithm == DenominationAlgorithm.FixedUSD)
			{
				try
				{
					var exchangeRates = await SmartBitClient.GetExchangeRatesAsync(cancel);
					decimal price = exchangeRates.Single(x => x.Code == "USD").Rate;
					decimal denominationUSD = (decimal)Global.Config.DenominationUSD;
					decimal denominationBTC = denominationUSD / price;
					Denomination = new Money(denominationBTC, MoneyUnit.BTC);
				}
				catch
				{
					Denomination = Global.Config.DenominationBTC;
				}
			}
			else if (Global.Config.DenominationAlgorithm == DenominationAlgorithm.FixedBTC)
			{
				Denomination = Global.Config.DenominationBTC;
			}
			else
			{
				throw new NotSupportedException(Global.Config.DenominationAlgorithm.ToString());
			}
		}

		#region IDisposable Support
		private bool _disposedValue = false; // To detect redundant calls

		protected virtual void Dispose(bool disposing)
		{
			if (!_disposedValue)
			{
				if (disposing)
				{
					_ctsPhaseCancel?.Dispose();
					SmartBitClient?.Dispose();
				}

				// TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
				// TODO: set large fields to null.

				_disposedValue = true;
			}
		}

		// TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
		// ~TumblerStateMachine() {
		//   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
		//   Dispose(false);
		// }

		// This code added to correctly implement the disposable pattern.
		public void Dispose()
		{
			// Do not change this code. Put cleanup code in Dispose(bool disposing) above.
			Dispose(true);
			// TODO: uncomment the following line if the finalizer is overridden above.
			// GC.SuppressFinalize(this);
		}
		#endregion
	}
}
