import React from 'react';
import { DataSourceRef, getDefaultTimeRange, LoadingState } from '@grafana/data';

import { variableAdapters } from '../adapters';
import { createQueryVariableAdapter } from './adapter';
import { reduxTester } from '../../../../test/core/redux/reduxTester';
import { getPreloadedState, getRootReducer, RootReducerType } from '../state/helpers';
import { QueryVariableModel, VariableHide, VariableQueryEditorProps, VariableRefresh, VariableSort } from '../types';
import {
  addVariable,
  changeVariableProp,
  setCurrentVariableValue,
  variableStateCompleted,
  variableStateFailed,
  variableStateFetching,
} from '../state/sharedReducer';
import {
  changeQueryVariableDataSource,
  changeQueryVariableQuery,
  flattenQuery,
  hasSelfReferencingQuery,
  initQueryVariableEditor,
  updateQueryVariableOptions,
} from './actions';
import { updateVariableOptions } from './reducer';
import {
  addVariableEditorError,
  changeVariableEditorExtended,
  initialVariableEditorState,
  removeVariableEditorError,
  setIdInEditor,
} from '../editor/reducer';
import { LegacyVariableQueryEditor } from '../editor/LegacyVariableQueryEditor';
import { expect } from 'test/lib/common';
import { updateOptions } from '../state/actions';
import { notifyApp } from '../../../core/reducers/appNotification';
import { silenceConsoleOutput } from '../../../../test/core/utils/silenceConsoleOutput';
import { getTimeSrv, setTimeSrv, TimeSrv } from '../../dashboard/services/TimeSrv';
import { setVariableQueryRunner, VariableQueryRunner } from './VariableQueryRunner';
import { setDataSourceSrv } from '@grafana/runtime';
import { variablesInitTransaction } from '../state/transactionReducer';
import { ALL_VARIABLE_TEXT, ALL_VARIABLE_VALUE } from '../constants';
import { toKeyedAction } from '../state/keyedVariablesReducer';
import { toKeyedVariableIdentifier, toVariablePayload } from '../utils';

const mocks: Record<string, any> = {
  datasource: {
    metricFindQuery: jest.fn().mockResolvedValue([]),
  },
  dataSourceSrv: {
    get: (ref: DataSourceRef) => Promise.resolve(mocks[ref.uid!]),
    getList: jest.fn().mockReturnValue([]),
  },
  pluginLoader: {
    importDataSourcePlugin: jest.fn().mockResolvedValue({ components: {} }),
  },
  VariableQueryEditor(props: VariableQueryEditorProps) {
    return <div>this is a variable query editor</div>;
  },
};

setDataSourceSrv(mocks.dataSourceSrv as any);

jest.mock('../../plugins/plugin_loader', () => ({
  importDataSourcePlugin: () => mocks.pluginLoader.importDataSourcePlugin(),
}));

jest.mock('../../templating/template_srv', () => ({
  replace: jest.fn().mockReturnValue(''),
}));

describe('query actions', () => {
  let originalTimeSrv: TimeSrv;

  beforeEach(() => {
    originalTimeSrv = getTimeSrv();
    setTimeSrv({
      timeRange: jest.fn().mockReturnValue(getDefaultTimeRange()),
    } as unknown as TimeSrv);
    setVariableQueryRunner(new VariableQueryRunner());
  });

  afterEach(() => {
    setTimeSrv(originalTimeSrv);
  });

  variableAdapters.setInit(() => [createQueryVariableAdapter()]);

  describe('when updateQueryVariableOptions is dispatched but there is no ongoing transaction', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: false });
      const optionsMetrics = [createMetric('A'), createMetric('B')];

      mockDatasourceMetrics(variable, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenAsyncActionIsDispatched(updateQueryVariableOptions(toKeyedVariableIdentifier(variable)), true);

      tester.thenNoActionsWhereDispatched();
    });
  });

  describe('when updateQueryVariableOptions is dispatched for variable without both tags and includeAll', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: false });
      const optionsMetrics = [createMetric('A'), createMetric('B')];

      mockDatasourceMetrics(variable, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(updateQueryVariableOptions(toKeyedVariableIdentifier(variable)), true);

      const option = createOption('A');
      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update))),
        toKeyedAction('key', setCurrentVariableValue(toVariablePayload(variable, { option })))
      );
    });
  });

  describe('when updateQueryVariableOptions is dispatched for variable with includeAll but without tags', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const optionsMetrics = [createMetric('A'), createMetric('B')];

      mockDatasourceMetrics(variable, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(updateQueryVariableOptions(toKeyedVariableIdentifier(variable)), true);

      const option = createOption(ALL_VARIABLE_TEXT, ALL_VARIABLE_VALUE);
      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update))),
        toKeyedAction('key', setCurrentVariableValue(toVariablePayload(variable, { option })))
      );
    });
  });

  describe('when updateQueryVariableOptions is dispatched for variable open in editor', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const optionsMetrics = [createMetric('A'), createMetric('B')];

      mockDatasourceMetrics(variable, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenActionIsDispatched(toKeyedAction('key', setIdInEditor({ id: variable.id })))
        .whenAsyncActionIsDispatched(updateQueryVariableOptions(toKeyedVariableIdentifier(variable)), true);

      const option = createOption(ALL_VARIABLE_TEXT, ALL_VARIABLE_VALUE);
      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', removeVariableEditorError({ errorProp: 'update' })),
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update))),
        toKeyedAction('key', setCurrentVariableValue(toVariablePayload(variable, { option })))
      );
    });
  });

  describe('when updateQueryVariableOptions is dispatched for variable with searchFilter', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const optionsMetrics = [createMetric('A'), createMetric('B')];

      mockDatasourceMetrics(variable, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenActionIsDispatched(toKeyedAction('key', setIdInEditor({ id: variable.id })))
        .whenAsyncActionIsDispatched(updateQueryVariableOptions(toKeyedVariableIdentifier(variable), 'search'), true);

      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', removeVariableEditorError({ errorProp: 'update' })),
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update)))
      );
    });
  });

  describe('when updateQueryVariableOptions is dispatched and fails for variable open in editor', () => {
    silenceConsoleOutput();
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const error = { message: 'failed to fetch metrics' };

      mocks[variable.datasource!.uid!].metricFindQuery = jest.fn(() => Promise.reject(error));

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenActionIsDispatched(toKeyedAction('key', setIdInEditor({ id: variable.id })))
        .whenAsyncActionIsDispatched(updateOptions(toKeyedVariableIdentifier(variable)), true);

      tester.thenDispatchedActionsPredicateShouldEqual((dispatchedActions) => {
        const expectedNumberOfActions = 5;

        expect(dispatchedActions[0]).toEqual(toKeyedAction('key', variableStateFetching(toVariablePayload(variable))));
        expect(dispatchedActions[1]).toEqual(toKeyedAction('key', removeVariableEditorError({ errorProp: 'update' })));
        expect(dispatchedActions[2]).toEqual(
          toKeyedAction('key', addVariableEditorError({ errorProp: 'update', errorText: error.message }))
        );
        expect(dispatchedActions[3]).toEqual(
          toKeyedAction(
            'key',
            variableStateFailed(toVariablePayload(variable, { error: { message: 'failed to fetch metrics' } }))
          )
        );
        expect(dispatchedActions[4].type).toEqual(notifyApp.type);
        expect(dispatchedActions[4].payload.title).toEqual('Templating [0]');
        expect(dispatchedActions[4].payload.text).toEqual('Error updating options: failed to fetch metrics');
        expect(dispatchedActions[4].payload.severity).toEqual('error');

        return dispatchedActions.length === expectedNumberOfActions;
      });
    });
  });

  describe('when initQueryVariableEditor is dispatched', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const testMetricSource = { name: 'test', value: 'test', meta: {} };
      const editor = mocks.VariableQueryEditor;

      mocks.dataSourceSrv.getList = jest.fn().mockReturnValue([testMetricSource]);
      mocks.pluginLoader.importDataSourcePlugin = jest.fn().mockResolvedValue({
        components: { VariableQueryEditor: editor },
      });

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(initQueryVariableEditor(toKeyedVariableIdentifier(variable)), true);

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction(
          'key',
          changeVariableEditorExtended({ dataSource: mocks.datasource, VariableQueryEditor: editor })
        )
      );
    });
  });

  describe('when initQueryVariableEditor is dispatched and metricsource without value is available', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const testMetricSource = { name: 'test', value: null as unknown as string, meta: {} };
      const editor = mocks.VariableQueryEditor;

      mocks.dataSourceSrv.getList = jest.fn().mockReturnValue([testMetricSource]);
      mocks.pluginLoader.importDataSourcePlugin = jest.fn().mockResolvedValue({
        components: { VariableQueryEditor: editor },
      });

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(initQueryVariableEditor(toKeyedVariableIdentifier(variable)), true);

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction(
          'key',
          changeVariableEditorExtended({ dataSource: mocks.datasource, VariableQueryEditor: editor })
        )
      );
    });
  });

  describe('when initQueryVariableEditor is dispatched and no metric sources was found', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ includeAll: true });
      const editor = mocks.VariableQueryEditor;

      mocks.dataSourceSrv.getList = jest.fn().mockReturnValue([]);
      mocks.pluginLoader.importDataSourcePlugin = jest.fn().mockResolvedValue({
        components: { VariableQueryEditor: editor },
      });

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(initQueryVariableEditor(toKeyedVariableIdentifier(variable)), true);

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction(
          'key',
          changeVariableEditorExtended({ dataSource: mocks.datasource, VariableQueryEditor: editor })
        )
      );
    });
  });

  describe('when changeQueryVariableDataSource is dispatched', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ datasource: { uid: 'other' } });
      const editor = mocks.VariableQueryEditor;

      mocks.pluginLoader.importDataSourcePlugin = jest.fn().mockResolvedValue({
        components: { VariableQueryEditor: editor },
      });

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(
          changeQueryVariableDataSource(toKeyedVariableIdentifier(variable), { uid: 'datasource' }),
          true
        );

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction(
          'key',
          changeVariableEditorExtended({ dataSource: mocks.datasource, VariableQueryEditor: editor })
        )
      );
    });

    describe('and data source type changed', () => {
      it('then correct actions are dispatched', async () => {
        const variable = createVariable({ datasource: { uid: 'other' } });
        const editor = mocks.VariableQueryEditor;
        const previousDataSource: any = { type: 'previous' };
        const templatingState = {
          editor: {
            ...initialVariableEditorState,
            extended: { dataSource: previousDataSource, VariableQueryEditor: editor },
          },
        };
        const preloadedState = getPreloadedState('key', templatingState);

        mocks.pluginLoader.importDataSourcePlugin = jest.fn().mockResolvedValue({
          components: { VariableQueryEditor: editor },
        });

        const tester = await reduxTester<RootReducerType>({ preloadedState })
          .givenRootReducer(getRootReducer())
          .whenActionIsDispatched(
            toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
          )
          .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
          .whenAsyncActionIsDispatched(
            changeQueryVariableDataSource(toKeyedVariableIdentifier(variable), { uid: 'datasource' }),
            true
          );

        tester.thenDispatchedActionsShouldEqual(
          toKeyedAction('key', changeVariableProp(toVariablePayload(variable, { propName: 'query', propValue: '' }))),
          toKeyedAction(
            'key',
            changeVariableEditorExtended({ dataSource: mocks.datasource, VariableQueryEditor: editor })
          )
        );
      });
    });
  });

  describe('when changeQueryVariableDataSource is dispatched and editor is not configured', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ datasource: { uid: 'other' } });
      const editor = LegacyVariableQueryEditor;

      mocks.pluginLoader.importDataSourcePlugin = jest.fn().mockResolvedValue({
        components: {},
      });

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(
          changeQueryVariableDataSource(toKeyedVariableIdentifier(variable), { uid: 'datasource' }),
          true
        );

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction(
          'key',
          changeVariableEditorExtended({ dataSource: mocks.datasource, VariableQueryEditor: editor })
        )
      );
    });
  });

  describe('when changeQueryVariableQuery is dispatched', () => {
    it('then correct actions are dispatched', async () => {
      const optionsMetrics = [createMetric('A'), createMetric('B')];
      const variable = createVariable({ datasource: { uid: 'datasource' }, includeAll: true });

      const query = '$datasource';
      const definition = 'depends on datasource variable';

      mockDatasourceMetrics({ ...variable, query }, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(
          changeQueryVariableQuery(toKeyedVariableIdentifier(variable), query, definition),
          true
        );

      const option = createOption(ALL_VARIABLE_TEXT, ALL_VARIABLE_VALUE);
      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', removeVariableEditorError({ errorProp: 'query' })),
        toKeyedAction('key', changeVariableProp(toVariablePayload(variable, { propName: 'query', propValue: query }))),
        toKeyedAction(
          'key',
          changeVariableProp(toVariablePayload(variable, { propName: 'definition', propValue: definition }))
        ),
        toKeyedAction('key', variableStateFetching(toVariablePayload(variable))),
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update))),
        toKeyedAction('key', setCurrentVariableValue(toVariablePayload(variable, { option }))),
        toKeyedAction('key', variableStateCompleted(toVariablePayload(variable)))
      );
    });
  });

  describe('when changeQueryVariableQuery is dispatched for variable without tags', () => {
    it('then correct actions are dispatched', async () => {
      const optionsMetrics = [createMetric('A'), createMetric('B')];
      const variable = createVariable({ datasource: { uid: 'datasource' }, includeAll: true });

      const query = '$datasource';
      const definition = 'depends on datasource variable';

      mockDatasourceMetrics({ ...variable, query }, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(
          changeQueryVariableQuery(toKeyedVariableIdentifier(variable), query, definition),
          true
        );

      const option = createOption(ALL_VARIABLE_TEXT, ALL_VARIABLE_VALUE);
      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', removeVariableEditorError({ errorProp: 'query' })),
        toKeyedAction('key', changeVariableProp(toVariablePayload(variable, { propName: 'query', propValue: query }))),
        toKeyedAction(
          'key',
          changeVariableProp(toVariablePayload(variable, { propName: 'definition', propValue: definition }))
        ),
        toKeyedAction('key', variableStateFetching(toVariablePayload(variable))),
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update))),
        toKeyedAction('key', setCurrentVariableValue(toVariablePayload(variable, { option }))),
        toKeyedAction('key', variableStateCompleted(toVariablePayload(variable)))
      );
    });
  });

  describe('when changeQueryVariableQuery is dispatched for variable without tags and all', () => {
    it('then correct actions are dispatched', async () => {
      const optionsMetrics = [createMetric('A'), createMetric('B')];
      const variable = createVariable({ datasource: { uid: 'datasource' }, includeAll: false });
      const query = '$datasource';
      const definition = 'depends on datasource variable';

      mockDatasourceMetrics({ ...variable, query }, optionsMetrics);

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(
          changeQueryVariableQuery(toKeyedVariableIdentifier(variable), query, definition),
          true
        );

      const option = createOption('A');
      const update = { results: optionsMetrics, templatedRegex: '' };

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', removeVariableEditorError({ errorProp: 'query' })),
        toKeyedAction('key', changeVariableProp(toVariablePayload(variable, { propName: 'query', propValue: query }))),
        toKeyedAction(
          'key',
          changeVariableProp(toVariablePayload(variable, { propName: 'definition', propValue: definition }))
        ),
        toKeyedAction('key', variableStateFetching(toVariablePayload(variable))),
        toKeyedAction('key', updateVariableOptions(toVariablePayload(variable, update))),
        toKeyedAction('key', setCurrentVariableValue(toVariablePayload(variable, { option }))),
        toKeyedAction('key', variableStateCompleted(toVariablePayload(variable)))
      );
    });
  });

  describe('when changeQueryVariableQuery is dispatched with invalid query', () => {
    it('then correct actions are dispatched', async () => {
      const variable = createVariable({ datasource: { uid: 'datasource' }, includeAll: false });
      const query = `$${variable.name}`;
      const definition = 'depends on datasource variable';

      const tester = await reduxTester<RootReducerType>()
        .givenRootReducer(getRootReducer())
        .whenActionIsDispatched(
          toKeyedAction('key', addVariable(toVariablePayload(variable, { global: false, index: 0, model: variable })))
        )
        .whenActionIsDispatched(toKeyedAction('key', variablesInitTransaction({ uid: 'key' })))
        .whenAsyncActionIsDispatched(
          changeQueryVariableQuery(toKeyedVariableIdentifier(variable), query, definition),
          true
        );

      const errorText = 'Query cannot contain a reference to itself. Variable: $' + variable.name;

      tester.thenDispatchedActionsShouldEqual(
        toKeyedAction('key', addVariableEditorError({ errorProp: 'query', errorText }))
      );
    });
  });

  describe('hasSelfReferencingQuery', () => {
    it('when called with a string', () => {
      const query = '$query';
      const name = 'query';

      expect(hasSelfReferencingQuery(name, query)).toBe(true);
    });

    it('when called with an array', () => {
      const query = ['$query'];
      const name = 'query';

      expect(hasSelfReferencingQuery(name, query)).toBe(true);
    });

    it('when called with a simple object', () => {
      const query = { a: '$query' };
      const name = 'query';

      expect(hasSelfReferencingQuery(name, query)).toBe(true);
    });

    it('when called with a complex object', () => {
      const query = {
        level2: {
          level3: {
            query: 'query3',
            refId: 'C',
            num: 2,
            bool: true,
            arr: [
              { query: 'query4', refId: 'D', num: 4, bool: true },
              {
                query: 'query5',
                refId: 'E',
                num: 5,
                bool: true,
                arr: [{ query: '$query', refId: 'F', num: 6, bool: true }],
              },
            ],
          },
          query: 'query2',
          refId: 'B',
          num: 1,
          bool: false,
        },
        query: 'query1',
        refId: 'A',
        num: 0,
        bool: true,
        arr: [
          { query: 'query7', refId: 'G', num: 7, bool: true },
          {
            query: 'query8',
            refId: 'H',
            num: 8,
            bool: true,
            arr: [{ query: 'query9', refId: 'I', num: 9, bool: true }],
          },
        ],
      };
      const name = 'query';

      expect(hasSelfReferencingQuery(name, query)).toBe(true);
    });

    it('when called with a number', () => {
      const query = 1;
      const name = 'query';

      expect(hasSelfReferencingQuery(name, query)).toBe(false);
    });
  });

  describe('flattenQuery', () => {
    it('when called with a complex object', () => {
      const query = {
        level2: {
          level3: {
            query: '${query3}',
            refId: 'C',
            num: 2,
            bool: true,
            arr: [
              { query: '${query4}', refId: 'D', num: 4, bool: true },
              {
                query: '${query5}',
                refId: 'E',
                num: 5,
                bool: true,
                arr: [{ query: '${query6}', refId: 'F', num: 6, bool: true }],
              },
            ],
          },
          query: '${query2}',
          refId: 'B',
          num: 1,
          bool: false,
        },
        query: '${query1}',
        refId: 'A',
        num: 0,
        bool: true,
        arr: [
          { query: '${query7}', refId: 'G', num: 7, bool: true },
          {
            query: '${query8}',
            refId: 'H',
            num: 8,
            bool: true,
            arr: [{ query: '${query9}', refId: 'I', num: 9, bool: true }],
          },
        ],
      };

      expect(flattenQuery(query)).toEqual({
        query: '${query1}',
        refId: 'A',
        num: 0,
        bool: true,
        level2_query: '${query2}',
        level2_refId: 'B',
        level2_num: 1,
        level2_bool: false,
        level2_level3_query: '${query3}',
        level2_level3_refId: 'C',
        level2_level3_num: 2,
        level2_level3_bool: true,
        level2_level3_arr_0_query: '${query4}',
        level2_level3_arr_0_refId: 'D',
        level2_level3_arr_0_num: 4,
        level2_level3_arr_0_bool: true,
        level2_level3_arr_1_query: '${query5}',
        level2_level3_arr_1_refId: 'E',
        level2_level3_arr_1_num: 5,
        level2_level3_arr_1_bool: true,
        level2_level3_arr_1_arr_0_query: '${query6}',
        level2_level3_arr_1_arr_0_refId: 'F',
        level2_level3_arr_1_arr_0_num: 6,
        level2_level3_arr_1_arr_0_bool: true,
        arr_0_query: '${query7}',
        arr_0_refId: 'G',
        arr_0_num: 7,
        arr_0_bool: true,
        arr_1_query: '${query8}',
        arr_1_refId: 'H',
        arr_1_num: 8,
        arr_1_bool: true,
        arr_1_arr_0_query: '${query9}',
        arr_1_arr_0_refId: 'I',
        arr_1_arr_0_num: 9,
        arr_1_arr_0_bool: true,
      });
    });
  });
});

function mockDatasourceMetrics(variable: QueryVariableModel, optionsMetrics: any[]) {
  const metrics: Record<string, any[]> = {
    [variable.query]: optionsMetrics,
  };

  const { metricFindQuery } = mocks[variable.datasource?.uid!];

  metricFindQuery.mockReset();
  metricFindQuery.mockImplementation((query: string) => Promise.resolve(metrics[query] ?? []));
}

function createVariable(extend?: Partial<QueryVariableModel>): QueryVariableModel {
  return {
    type: 'query',
    id: '0',
    rootStateKey: 'key',
    global: false,
    current: createOption(''),
    options: [],
    query: 'options-query',
    name: 'Constant',
    label: '',
    hide: VariableHide.dontHide,
    skipUrlSync: false,
    index: 0,
    datasource: { uid: 'datasource' },
    definition: '',
    sort: VariableSort.alphabeticalAsc,
    refresh: VariableRefresh.onDashboardLoad,
    regex: '',
    multi: true,
    includeAll: true,
    state: LoadingState.NotStarted,
    error: null,
    description: null,
    ...(extend ?? {}),
  };
}

function createOption(text: string, value?: string) {
  const metric = createMetric(text);
  return {
    ...metric,
    value: value ?? metric.text,
    selected: false,
  };
}

function createMetric(value: string) {
  return {
    text: value,
  };
}
