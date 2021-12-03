import React, { FC, FormEvent } from 'react';
import { css } from '@emotion/css';
import { HorizontalGroup, RadioButtonGroup, stylesFactory, useTheme, Checkbox } from '@grafana/ui';
import { GrafanaTheme, SelectableValue } from '@grafana/data';
import { SortPicker } from 'app/core/components/Select/SortPicker';
import { TagFilter } from 'app/core/components/TagFilter/TagFilter';
import { SearchSrv } from 'app/core/services/search_srv';
import { DashboardQuery, SearchLayout } from '../types';
import { config } from '@grafana/runtime';

export const layoutOptions = [
  { value: SearchLayout.Folders, icon: 'folder', ariaLabel: 'View by folders' },
  { value: SearchLayout.List, icon: 'list-ul', ariaLabel: 'View as list' },
];

if (config.featureToggles.dashboardPreviews) {
  layoutOptions.push({
    value: SearchLayout.Grid,
    icon: 'microsoft', // looks like a grid ¯\_(ツ)_/¯
    ariaLabel: 'View as Grid',
  });
}

const searchSrv = new SearchSrv();

interface Props {
  onLayoutChange: (layout: SearchLayout) => void;
  onSortChange: (value: SelectableValue) => void;
  onStarredFilterChange?: (event: FormEvent<HTMLInputElement>) => void;
  onTagFilterChange: (tags: string[]) => void;
  query: DashboardQuery;
  showStarredFilter?: boolean;
  hideLayout?: boolean;
}

export const ActionRow: FC<Props> = ({
  onLayoutChange,
  onSortChange,
  onStarredFilterChange = () => {},
  onTagFilterChange,
  query,
  showStarredFilter,
  hideLayout,
}) => {
  const theme = useTheme();
  const styles = getStyles(theme);

  return (
    <div className={styles.actionRow}>
      <div className={styles.rowContainer}>
        <HorizontalGroup spacing="md" width="auto">
          {!hideLayout ? (
            <RadioButtonGroup options={layoutOptions} onChange={onLayoutChange} value={query.layout} />
          ) : null}
          <SortPicker onChange={onSortChange} value={query.sort?.value} />
        </HorizontalGroup>
      </div>
      <HorizontalGroup spacing="md" width="auto">
        {showStarredFilter && (
          <div className={styles.checkboxWrapper}>
            <Checkbox label="Filter by starred" onChange={onStarredFilterChange} value={query.starred} />
          </div>
        )}
        <TagFilter isClearable tags={query.tag} tagOptions={searchSrv.getDashboardTags} onChange={onTagFilterChange} />
      </HorizontalGroup>
    </div>
  );
};

ActionRow.displayName = 'ActionRow';

const getStyles = stylesFactory((theme: GrafanaTheme) => {
  return {
    actionRow: css`
      display: none;

      @media only screen and (min-width: ${theme.breakpoints.md}) {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: ${theme.spacing.lg} 0;
        width: 100%;
      }
    `,
    rowContainer: css`
      margin-right: ${theme.spacing.md};
    `,
    checkboxWrapper: css`
      label {
        line-height: 1.2;
      }
    `,
  };
});
