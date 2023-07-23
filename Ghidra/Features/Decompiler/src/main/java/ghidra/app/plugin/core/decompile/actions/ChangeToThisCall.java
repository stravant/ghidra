/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.decompile.actions;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Parameter;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ChangeToThisCall extends AbstractDecompilerAction {

	public ChangeToThisCall() {
		super("Change to __thiscall");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionEditSignature"));
		setPopupMenuData(new MenuData(new String[] { "Change to __thiscall" }, "Decompile"));
	}

	/**
	 * Get function affected by specified action context
	 * 
	 * @param function is the current decompiled function which will be the default
	 *                 if no other
	 *                 function identified by context token.
	 * @param context  decompiler action context
	 * @return the function associated with the current context token. If no
	 *         function corresponds
	 *         to context token the decompiled function will be returned.
	 */
	private Function getFunction(Function function, DecompilerActionContext context) {
		// try to look up the function that is at the current cursor location
		// If there isn't one, just use the function we are in.
		Function tokenFunction = getFunction(context);
		return tokenFunction != null ? tokenFunction : function;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}
		return getFunction(function, context) != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Function function = getFunction(context.getFunction(), context);

		Program p = function.getProgram();
		int id = p.startTransaction("Edit Function");
		try {
			if (!function.getCallingConventionName().equals("__thiscall")) {
				Parameter[] params = function.getParameters();
				// Remove first param if there are any, this will replace it
				if (params.length > 0) {
					Parameter[] newParams = new Parameter[params.length - 1];
					System.arraycopy(params, 1, newParams, 0, params.length - 1);
					params = newParams;
				}
				function.updateFunction("__thiscall", function.getReturn(),
						FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED, params);
				function.setCallingConvention("__thiscall");
			}
		} catch (DuplicateNameException e) {
			System.out.println(e.getMessage());
		} catch (InvalidInputException e) {
			System.out.println(e.getMessage());
		} finally {
			p.endTransaction(id, true);
		}
	}
}
