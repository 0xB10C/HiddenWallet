using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace System
{
    public static class ByteHelpers
    {
		public static byte[] Combine(params byte[][] arrays)
		{
			var len = arrays.Select(a => a.Length).Sum();
			int offset = 0;
			var combined = new byte[len];
			foreach (var array in arrays)
			{
				Array.Copy(array, 0, combined, offset, array.Length);
				offset += array.Length;
			}
			return combined;
		}
	}
}
